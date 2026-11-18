#!/usr/bin/env node
// Make an ADMIN_USERS entry without ever writing the password anywhere.
//   node hash-password.js <username>
//   docker compose run --rm mailcow-mcp-server node hash-password.js <username>
// Prints:  ADMIN_USERS=<username>:scrypt....   -> put that line in .env (or append ",<username>:scrypt..." to an existing one)
import readline from "node:readline";
import { hashPassword, verifyPassword } from "./admin-users.js";

const user = (process.argv[2] || "").trim().toLowerCase();
if (!/^[a-z0-9._@-]{2,64}$/.test(user)) {
  console.error("Usage: node hash-password.js <username>   (letters, digits, . _ - @; 2-64 chars)");
  process.exit(1);
}

function ask(prompt) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (s.includes(prompt)) rl.output.write(s); }; // hide typed characters
    rl.question(prompt, (answer) => { rl.close(); process.stdout.write("\n"); resolve(answer); });
  });
}

const pw1 = await ask("New admin password: ");
if (pw1.length < 12) { console.error("Use at least 12 characters."); process.exit(1); }
const pw2 = await ask("Repeat password: ");
if (pw1 !== pw2) { console.error("Passwords do not match."); process.exit(1); }

const hash = hashPassword(pw1);
if (!verifyPassword(pw1, hash)) { console.error("Self-check failed."); process.exit(1); }

const out = process.argv.indexOf("--out") > 0 ? process.argv[process.argv.indexOf("--out") + 1] : null;
if (out) {
  // used by set-admin-password.sh: hand the entry over through the data volume
  (await import("node:fs")).writeFileSync(out, `${user}:${hash}\n`, { mode: 0o600 });
} else {
  console.log(`\nADMIN_USERS=${user}:${hash}\n`);
  console.log("Put that line in .env, then restart:  docker compose up -d");
}
