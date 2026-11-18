import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import express from "express";

const rand = (n = 32) => crypto.randomBytes(n).toString("base64url");
const sha = (s) => crypto.createHash("sha256").update(String(s)).digest("base64url");
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const TOKEN_TTL_MS = 90 * 24 * 60 * 60 * 1000; // a sign-in lasts 90 days, then the user signs in again

// ---- Encrypted, persistent session store (survives container restarts) ----
// Maps sha256(access_token) -> { email, enc(password), exp }. Passwords are AES-256-GCM encrypted
// with a key derived from SESSION_SECRET; the raw access token is never stored.
export function createSessionStore({ file, secret }) {
  const key = crypto.createHash("sha256").update("mail-mcp-sessions:" + secret).digest();
  let data = {};
  try { data = JSON.parse(fs.readFileSync(file, "utf8")); } catch { data = {}; }

  const save = () => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = file + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
    fs.renameSync(tmp, file);
  };
  const enc = (plain) => {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv("aes-256-gcm", key, iv);
    const ct = Buffer.concat([c.update(plain, "utf8"), c.final()]);
    return [iv, c.getAuthTag(), ct].map((b) => b.toString("base64url")).join(".");
  };
  const dec = (blob) => {
    const [iv, tag, ct] = blob.split(".").map((s) => Buffer.from(s, "base64url"));
    const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
  };
  const prune = () => {
    const now = Date.now();
    let changed = false;
    for (const [k, v] of Object.entries(data)) if (v.exp < now) { delete data[k]; changed = true; }
    if (changed) save();
  };
  setInterval(prune, 60 * 60 * 1000).unref();
  prune();

  return {
    create(email, password) {
      const token = rand(32);
      data[sha(token)] = { email, pw: enc(password), exp: Date.now() + TOKEN_TTL_MS, created: Date.now() };
      save();
      return token;
    },
    get(token) {
      const s = data[sha(token)];
      if (!s || s.exp < Date.now()) return null;
      try { return { email: s.email, password: dec(s.pw) }; } catch { return null; }
    },
    revoke(token) { if (data[sha(token)]) { delete data[sha(token)]; save(); } },
    count() { return Object.keys(data).length; },
  };
}

export function setupOAuth(app, { baseUrl, verifyLogin, sessions, mailDomain, brandName = "Mail MCP" }) {
  const clients = new Map();
  const codes = new Map();
  const fails = new Map(); // ip -> wrong-login count, reset every 10 minutes
  const urlencoded = express.urlencoded({ extended: false });

  setInterval(() => {
    fails.clear();
    const now = Date.now();
    for (const [k, v] of codes) if (v.exp < now) codes.delete(k);
  }, 10 * 60 * 1000).unref();

  app.use(["/.well-known", "/register", "/token"], (req, res, next) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "content-type, authorization, mcp-protocol-version");
    if (req.method === "OPTIONS") return res.sendStatus(204);
    next();
  });

  // resource = the URL the client connects to: /mcp, or the bare domain
  const prm = (req, res) =>
    res.json({ resource: req.path.endsWith("/mcp") ? `${baseUrl}/mcp` : baseUrl, authorization_servers: [baseUrl], bearer_methods_supported: ["header"] });
  app.get("/.well-known/oauth-protected-resource", prm);
  app.get("/.well-known/oauth-protected-resource/mcp", prm);

  app.get("/.well-known/oauth-authorization-server", (_req, res) =>
    res.json({
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      registration_endpoint: `${baseUrl}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
    })
  );

  app.post("/register", (req, res) => {
    const b = req.body || {};
    const uris = Array.isArray(b.redirect_uris) ? b.redirect_uris.filter((u) => typeof u === "string") : [];
    if (!uris.length) return res.status(400).json({ error: "invalid_redirect_uri", error_description: "redirect_uris required" });
    if (clients.size > 500) clients.delete(clients.keys().next().value);
    const client_id = rand(16);
    clients.set(client_id, { redirect_uris: uris });
    res.status(201).json({
      client_id,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris: uris,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      client_name: b.client_name,
    });
  });

  const check = (q) => {
    const c = clients.get(q.client_id);
    if (!c) return "Unknown client. Start the connection again from your MCP client.";
    if (!c.redirect_uris.includes(q.redirect_uri)) return "Redirect address not registered.";
    if (q.response_type !== "code") return "Unsupported response type.";
    if (!q.code_challenge || q.code_challenge_method !== "S256") return "PKCE (S256) is required.";
    return null;
  };

  const page = (q, err, email = "") => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in - ${esc(brandName)}</title>
<style>
:root{--bg:#f4f6fa;--card:#fff;--text:#1a1f2b;--muted:#5d6678;--line:#d6dbe5;--accent:#1f5eff;--err:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#181c24;--text:#e8ebf2;--muted:#9aa3b5;--line:#2c3341;--accent:#5b8cff;--err:#ff8a80}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:16px}
.card{width:100%;max-width:400px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px}
h1{font-size:20px;margin:0 0 6px}p{color:var(--muted);margin:0 0 20px;font-size:14px;line-height:1.5}
label{display:block;font-size:13px;font-weight:600;margin:14px 0 6px}
input[type=email],input[type=password]{width:100%;padding:11px 12px;font-size:16px;border:1px solid var(--line);border-radius:8px;background:transparent;color:var(--text)}
input:focus{outline:2px solid var(--accent);outline-offset:1px}
button{margin-top:20px;width:100%;padding:12px;font-size:16px;font-weight:600;border:0;border-radius:8px;background:var(--accent);color:#fff;cursor:pointer}
.err{color:var(--err);font-size:14px;margin:0 0 8px}.foot{margin-top:16px;font-size:12px;color:var(--muted);text-align:center}
</style></head><body><main class="card">
<h1>Sign in to your mailbox</h1>
<p>Use your ${mailDomain ? `@${esc(mailDomain)} ` : ""}email address and password to connect your mailbox to ${esc(brandName)}.</p>
${err ? `<p class="err" role="alert">${esc(err)}</p>` : ""}
<form method="post" action="/authorize">
${["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "response_type"]
  .map((k) => `<input type="hidden" name="${k}" value="${esc(q[k])}">`).join("")}
<label for="email">Email</label>
<input id="email" type="email" name="email" value="${esc(email)}" autocomplete="username" required ${email ? "" : "autofocus"}>
<label for="password">Password</label>
<input id="password" type="password" name="password" autocomplete="current-password" required ${email ? "autofocus" : ""}>
<button type="submit">Sign in and connect</button>
</form>
<div class="foot">Your password is checked against the mail server and stored encrypted.</div>
</main></body></html>`;

  app.get("/authorize", (req, res) => {
    const err = check(req.query);
    if (err) return res.status(400).send(esc(err));
    res.send(page(req.query));
  });

  app.post("/authorize", urlencoded, async (req, res) => {
    const q = req.body || {};
    const err = check(q);
    if (err) return res.status(400).send(esc(err));
    const ip = req.ip || "unknown";
    if ((fails.get(ip) || 0) >= 5) return res.status(429).send(page(q, "Too many failed sign-ins. Try again in 10 minutes.", q.email));

    const email = String(q.email || "").trim().toLowerCase();
    const password = String(q.password || "");
    if (!email || !password) return res.status(400).send(page(q, "Enter your email and password.", email));
    if (mailDomain && !email.endsWith("@" + mailDomain.toLowerCase()))
      return res.status(401).send(page(q, `Only @${mailDomain} mailboxes can sign in here.`, email));

    const ok = await verifyLogin(email, password).catch(() => false);
    if (!ok) {
      fails.set(ip, (fails.get(ip) || 0) + 1);
      console.error(`login failed for ${email}`);
      return res.status(401).send(page(q, "Wrong email or password.", email));
    }
    console.error(`login ok for ${email}`);

    const code = rand(24);
    codes.set(code, { client_id: q.client_id, redirect_uri: q.redirect_uri, challenge: q.code_challenge, email, password, exp: Date.now() + 5 * 60 * 1000 });
    const u = new URL(q.redirect_uri);
    u.searchParams.set("code", code);
    if (q.state) u.searchParams.set("state", q.state);
    res.redirect(302, u.toString());
  });

  app.post("/token", urlencoded, (req, res) => {
    const b = req.body || {};
    if (b.grant_type !== "authorization_code") return res.status(400).json({ error: "unsupported_grant_type" });
    const c = codes.get(b.code);
    codes.delete(b.code);
    const hash = sha(b.code_verifier || "");
    if (!c || c.exp < Date.now() || c.client_id !== b.client_id || c.redirect_uri !== b.redirect_uri || hash !== c.challenge)
      return res.status(400).json({ error: "invalid_grant" });
    const access_token = sessions.create(c.email, c.password);
    res.set("Cache-Control", "no-store");
    res.json({ access_token, token_type: "Bearer", expires_in: Math.floor(TOKEN_TTL_MS / 1000) });
  });
}
