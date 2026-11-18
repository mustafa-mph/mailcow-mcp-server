#!/usr/bin/env node
// mailcow-mcp-server: remote MCP server for managing a Mailcow mail server through its API.
// Users sign in with their Mailcow mailbox (checked by an IMAP login). Emails listed in ADMIN_EMAILS
// get the admin tools; everyone else gets self-service tools for their own mailbox only.
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
dotenv.config({ path: path.join(path.dirname(fileURLToPath(import.meta.url)), ".env") });

import express from "express";
import { ImapFlow } from "imapflow";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { setupOAuth, createSessionStore } from "./oauth.js";
import { registerMailcowTools, mailcowEnabled, mailcowReadOnly, isAdminEmail } from "./mailcow.js";
import { parseAdminUsers, verifyPassword } from "./admin-users.js";

const die = (msg) => { console.error(msg); process.exit(1); };

// ---- Config ----
if (!mailcowEnabled) die("MAILCOW_API_URL and MAILCOW_API_KEY must be set. See .env.example.");
const MAILCOW_HOST = new URL(process.env.MAILCOW_API_URL).hostname;

const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");
if (!/^https?:\/\//.test(PUBLIC_BASE_URL)) die("PUBLIC_BASE_URL must be set to the public URL of this server, e.g. https://mcp-admin.example.com");

const SESSION_SECRET = process.env.SESSION_SECRET || "";
if (SESSION_SECRET.length < 32) die("SESSION_SECRET must be a random string of at least 32 characters (openssl rand -hex 32).");

const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN || ""; // optional static admin token (for scripts / headless clients)
if (AUTH_TOKEN && AUTH_TOKEN.length < 32) die("MCP_AUTH_TOKEN must be at least 32 characters when set.");

// Sign-in checks the mailbox password with an IMAP login; defaults to the Mailcow host itself
const IMAP_HOST = process.env.USER_IMAP_HOST || MAILCOW_HOST;
const IMAP_PORT = Number(process.env.USER_IMAP_PORT || "993");
const IMAP_SECURE = (process.env.USER_IMAP_SECURE || "true") === "true";
const MAIL_DOMAIN = (process.env.USER_MAIL_DOMAIN || "").trim();
const BRAND_NAME = process.env.BRAND_NAME || "Mailcow MCP";
const ADMINS_ONLY = (process.env.ADMINS_ONLY || "false") === "true"; // true = non-admins cannot sign in at all
// Local admin logins (username + scrypt hash), checked by this server - not mailboxes
const ADMIN_USERS = parseAdminUsers(process.env.ADMIN_USERS);
// MAILBOX_SIGNIN=false turns off mailbox (IMAP) sign-in completely, so only ADMIN_USERS can sign in
const MAILBOX_SIGNIN = (process.env.MAILBOX_SIGNIN || "true") === "true";
if (!MAILBOX_SIGNIN && ADMIN_USERS.size === 0 && !process.env.MCP_AUTH_TOKEN) die("MAILBOX_SIGNIN=false needs ADMIN_USERS (run ./set-admin-password.sh <username>) or MCP_AUTH_TOKEN.");
const isAdminUser = (id) => ADMIN_USERS.has(String(id || "").toLowerCase());

// True only when the mail server explicitly rejected the username/password (not for network errors).
function isAuthError(err) {
  if (!err) return false;
  if (err.authenticationFailed === true) return true;
  return /AUTHENTICATIONFAILED|authentication failed|invalid credentials/i.test(`${err.responseText || ""} ${err.message || ""}`);
}

// "ok" | "auth_failed" | "unavailable"
// Admin usernames are checked against ADMIN_USERS; anything else is treated as a mailbox (IMAP login).
async function checkLogin(email, password) {
  const id = String(email || "").toLowerCase();
  if (isAdminUser(id)) return verifyPassword(password, ADMIN_USERS.get(id)) ? "ok" : "auth_failed";
  if (!MAILBOX_SIGNIN || !id.includes("@")) return "auth_failed"; // removed admin user, or mailbox sign-in disabled
  const client = new ImapFlow({ host: IMAP_HOST, port: IMAP_PORT, secure: IMAP_SECURE, auth: { user: email, pass: password }, logger: false });
  try {
    await client.connect();
    await client.logout().catch(() => {});
    return "ok";
  } catch (err) {
    return isAuthError(err) ? "auth_failed" : "unavailable";
  }
}

async function verifyLogin(email, password) {
  if (!isAdminUser(email) && ADMINS_ONLY && !isAdminEmail(email)) return false;
  return (await checkLogin(email, password)) === "ok";
}

// ---- HTTP app ----
const sessions = createSessionStore({ file: process.env.SESSION_FILE || "/data/sessions.json", secret: SESSION_SECRET });

const app = express();
app.set("trust proxy", Number(process.env.TRUST_PROXY_HOPS || "1"));
app.use(express.json({ limit: "2mb" }));
app.use((req, res, next) => {
  res.on("finish", () => { if (req.path !== "/healthz") console.error(`${req.method} ${req.originalUrl.split("?")[0]} -> ${res.statusCode}`); });
  next();
});

const loginLabel = !MAILBOX_SIGNIN ? "Admin username" : ADMIN_USERS.size ? "Admin username or mailbox email" : "Email";
setupOAuth(app, {
  baseUrl: PUBLIC_BASE_URL, verifyLogin, sessions, brandName: BRAND_NAME,
  mailDomain: ADMIN_USERS.size ? "" : MAIL_DOMAIN, // a domain filter would block admin usernames
  loginLabel,
  intro: !MAILBOX_SIGNIN
    ? `Sign in with your ${BRAND_NAME} admin username and password.`
    : ADMIN_USERS.size
      ? `Sign in with your ${BRAND_NAME} admin username, or with your mailbox email and password.`
      : undefined,
});

const sameSecret = (a, b) =>
  crypto.timingSafeEqual(crypto.createHash("sha256").update(String(a)).digest(), crypto.createHash("sha256").update(String(b)).digest());

function callerForToken(token) {
  if (!token) return null;
  if (AUTH_TOKEN && sameSecret(token, AUTH_TOKEN)) return { isAdmin: true };
  const s = sessions.get(token);
  if (!s) return null;
  if (isAdminUser(s.email)) return { isAdmin: true, session: s }; // local admin login: no mailbox, no self-service tools
  if (!MAILBOX_SIGNIN) return null;
  const isAdmin = isAdminEmail(s.email);
  if (ADMINS_ONLY && !isAdmin) return null;
  return { isAdmin, userEmail: s.email, session: s };
}

const isInitialize = (body) => (Array.isArray(body) ? body : [body]).some((m) => m && m.method === "initialize");

app.use((req, _res, next) => { if (req.path === "/") req.url = "/mcp" + req.url.slice(1); next(); });

app.post("/mcp", async (req, res) => {
  const auth = req.headers["authorization"] || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  const unauthorized = () => {
    res.set("WWW-Authenticate", `Bearer resource_metadata="${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource${req.originalUrl.startsWith("/mcp") ? "/mcp" : ""}"`);
    return res.status(401).json({ error: "Unauthorized" });
  };
  const caller = callerForToken(token);
  if (!caller) return unauthorized();

  // On every (re)connect, re-check the mailbox login. A changed password or a disabled mailbox
  // ends the sign-in, so the user must sign in again - and loses admin access if the mailbox is gone.
  if (caller.session && isInitialize(req.body)) {
    if ((await checkLogin(caller.session.email, caller.session.password)) === "auth_failed") {
      sessions.revoke(token);
      console.error(`saved password rejected for ${caller.session.email}: signed out`);
      return unauthorized();
    }
  }
  try {
    const server = new McpServer({ name: "mailcow-mcp-server", version: "1.0.0" });
    registerMailcowTools(server, caller);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => { transport.close(); server.close(); });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error("MCP request error:", err);
    if (!res.headersSent) res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/mcp", (_req, res) => res.status(405).json({ error: "Method not allowed (stateless server, use POST)" }));
app.get("/healthz", (_req, res) => res.status(200).send("ok"));

const PORT = Number(process.env.PORT || "3901");
app.listen(PORT, () => {
  console.error(
    `mailcow-mcp-server listening on :${PORT} | public URL ${PUBLIC_BASE_URL} | mailcow ${MAILCOW_HOST} (${mailcowReadOnly ? "read-only" : "read-write"})` +
      ` | admin logins: ${[...ADMIN_USERS.keys()].join(", ") || "none"}` +
      ` | mailbox sign-in: ${MAILBOX_SIGNIN ? `${IMAP_HOST}:${IMAP_PORT} (${ADMINS_ONLY ? "ADMIN_EMAILS only" : "all users"})` : "off"} | saved sign-ins: ${sessions.count()}`
  );
});
