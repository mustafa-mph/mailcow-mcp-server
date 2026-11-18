// Local admin accounts for the sign-in page (independent of mailboxes).
// ADMIN_USERS=alice:scrypt.16384.8.1.<salt>.<hash>,bob:scrypt....
// Hashes are made with:  node hash-password.js <username>   (never store plain passwords)
// The format uses no "$" so docker compose does not try to expand it.
import crypto from "node:crypto";

const KEYLEN = 64;

export function hashPassword(password, { N = 16384, r = 8, p = 1 } = {}) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(password).normalize("NFKC"), salt, KEYLEN, { N, r, p, maxmem: 64 * 1024 * 1024 });
  return ["scrypt", N, r, p, salt.toString("base64url"), hash.toString("base64url")].join(".");
}

export function verifyPassword(password, stored) {
  try {
    const [kind, N, r, p, saltB64, hashB64] = String(stored).split(".");
    if (kind !== "scrypt") return false;
    const expected = Buffer.from(hashB64, "base64url");
    const actual = crypto.scryptSync(String(password).normalize("NFKC"), Buffer.from(saltB64, "base64url"), expected.length, {
      N: Number(N), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024,
    });
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

// "alice:scrypt...,bob:scrypt..." -> Map(username -> hash). Usernames are case-insensitive.
export function parseAdminUsers(value) {
  const map = new Map();
  for (const entry of String(value || "").split(",").map((s) => s.trim()).filter(Boolean)) {
    const i = entry.indexOf(":");
    if (i < 1) { console.error(`ADMIN_USERS: ignoring malformed entry "${entry.slice(0, 20)}..."`); continue; }
    const user = entry.slice(0, i).trim().toLowerCase();
    const hash = entry.slice(i + 1).trim();
    if (!hash.startsWith("scrypt.")) { console.error(`ADMIN_USERS: "${user}" has no scrypt hash (use hash-password.js) - ignored`); continue; }
    map.set(user, hash);
  }
  return map;
}
