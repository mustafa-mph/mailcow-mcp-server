// Mailcow admin API tools (optional).
// Enabled when MAILCOW_API_URL and MAILCOW_API_KEY are set.
//  - Admin callers (owner token, or a signed-in email listed in ADMIN_EMAILS) get server management tools.
//  - Every signed-in user gets self-service tools limited strictly to their own mailbox.
import { z } from "zod";

const API_URL = (process.env.MAILCOW_API_URL || "").replace(/\/+$/, "");
const API_KEY = process.env.MAILCOW_API_KEY || "";
const READ_ONLY = (process.env.MAILCOW_API_ACCESS || "read-write").toLowerCase() === "read-only";
const TIMEOUT_MS = Number(process.env.MAILCOW_API_TIMEOUT_MS || "20000");
const ADMIN_EMAILS = new Set(
  (process.env.ADMIN_EMAILS || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean)
);

export const mailcowEnabled = Boolean(API_URL && API_KEY);
export const mailcowReadOnly = READ_ONLY;
export const isAdminEmail = (email) => ADMIN_EMAILS.has(String(email || "").toLowerCase());

const LOG_TYPES = ["postfix", "dovecot", "rspamd-history", "sogo", "netfilter", "autodiscover", "watchdog", "acme", "api", "ratelimited"];

// ---- HTTP client ----
async function api(method, path, body) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${API_URL}/api/v1/${path}`, {
      method,
      headers: { "X-API-Key": API_KEY, Accept: "application/json", ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
    const text = await res.text();
    let data;
    try { data = text ? JSON.parse(text) : null; } catch { data = text; }
    if (!res.ok) throw new Error(`Mailcow API ${res.status}: ${typeof data === "string" ? data.slice(0, 300) : JSON.stringify(data).slice(0, 300)}`);
    // write calls return [{type: "success"|"danger"|"error", msg: ...}]
    const list = Array.isArray(data) ? data : [data];
    const failed = list.filter((r) => r && typeof r === "object" && (r.type === "danger" || r.type === "error"));
    if (failed.length) throw new Error(`Mailcow refused: ${failed.map((f) => JSON.stringify(f.msg)).join("; ")}`);
    return data;
  } catch (err) {
    if (err.name === "AbortError") throw new Error(`Mailcow API timed out after ${TIMEOUT_MS} ms`);
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
const get = (path) => api("GET", path);
const post = (path, body) => api("POST", path, body);
const enc = encodeURIComponent;
const asArray = (d) => (Array.isArray(d) ? d : d && typeof d === "object" && Object.keys(d).length ? [d] : []);
const bool = (v) => (v === undefined ? undefined : v ? 1 : 0);
const clean = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined));
const mb = (bytes) => (bytes == null ? null : Math.round((Number(bytes) / 1048576) * 10) / 10);

const ok = (obj) => ({ content: [{ type: "text", text: JSON.stringify(obj, null, 2) }] });
const fail = (err) => ({ content: [{ type: "text", text: `Error: ${err.message}` }], isError: true });
const wrap = (fn) => async (args) => { try { return ok(await fn(args)); } catch (e) { return fail(e); } };
const needConfirm = (confirm, what) => {
  if (confirm !== true) throw new Error(`This permanently ${what}. Call again with confirm: true once the user has explicitly agreed.`);
};

// Compact views so the model is not flooded with Mailcow's very wide objects
const mailboxView = (m) => ({
  username: m.username, name: m.name, domain: m.domain, active: m.active === 1 || m.active === "1",
  quota_mb: mb(m.quota), used_mb: mb(m.quota_used), used_percent: m.percent_in_use, messages: m.messages,
  last_imap_login: m.last_imap_login ? new Date(Number(m.last_imap_login) * 1000).toISOString() : null,
  created: m.created, modified: m.modified,
});
const domainView = (d) => ({
  domain: d.domain_name, description: d.description, active: d.active === 1 || d.active === "1",
  mailboxes_used: d.mboxes_in_domain ?? null, mailboxes_max: d.max_num_mboxes_for_domain ?? null,
  aliases_used: d.aliases_in_domain ?? null, aliases_max: d.max_num_aliases_for_domain ?? null,
  quota_mb: mb(d.max_quota_for_domain), used_mb: mb(d.bytes_total), default_mailbox_quota_mb: mb(d.def_quota_for_mbox),
  max_mailbox_quota_mb: mb(d.max_quota_for_mbox), backupmx: d.backupmx === 1 || d.backupmx === "1",
});
const aliasView = (a) => ({ id: a.id, address: a.address, goto: a.goto, domain: a.domain, active: a.active === 1 || a.active === "1", comment: a.public_comment || undefined });
const syncView = (s) => ({
  id: s.id, mailbox: s.user2, source_host: s.host1, source_user: s.user1, active: s.active === 1 || s.active === "1",
  interval_min: s.mins_interval, last_run: s.last_run, success: s.success, exit_status: s.exit_status, is_running: s.is_running,
});
const queueView = (q) => ({ queue_id: q.queue_id, queue: q.queue_name, sender: q.sender, recipients: q.recipients, arrival: q.arrival_time ? new Date(q.arrival_time * 1000).toISOString() : undefined, size: q.message_size });
const quarantineView = (q) => ({ id: q.id, recipient: q.rcpt, sender: q.sender, subject: q.subject, score: q.score, action: q.action, created: q.created ? new Date(q.created * 1000).toISOString() : undefined });

// ---- Tool registration ----
export function registerMailcowTools(server, { isAdmin, userEmail }) {
  if (!mailcowEnabled) return;
  const write = !READ_ONLY;
  const RO = { readOnlyHint: true, openWorldHint: false };
  const W = { readOnlyHint: false, destructiveHint: false, openWorldHint: false };
  const D = { readOnlyHint: false, destructiveHint: true, openWorldHint: false };
  const t = (name, description, inputSchema, annotations, fn) =>
    server.registerTool(name, { description, inputSchema, annotations }, wrap(fn));

  // ---------- Self-service: only the signed-in user's own mailbox ----------
  if (userEmail) {
    const me = String(userEmail).toLowerCase();

    t("my_account", "Your mailbox account info from the mail server: quota, space used, message count, last login.", {}, RO, async () => {
      const m = await get(`get/mailbox/${enc(me)}`);
      if (!m || !m.username) throw new Error("Mailbox not found on the server.");
      return mailboxView(m);
    });

    t("my_aliases", "List alias addresses that deliver to your mailbox.", {}, RO, async () => {
      const all = asArray(await get("get/alias/all"));
      return all.filter((a) => String(a.goto || "").toLowerCase().split(",").map((s) => s.trim()).includes(me)).map(aliasView);
    });

    t("my_quarantine", "List spam-quarantined messages addressed to you.", {}, RO, async () => {
      const all = asArray(await get("get/quarantine/all"));
      return all.filter((q) => String(q.rcpt || "").toLowerCase() === me).map(quarantineView);
    });

    t("my_app_passwords", "List your app passwords (separate passwords for mail apps). The secrets themselves are never shown.", {}, RO, async () => {
      const list = asArray(await get(`get/app-passwd/all/${enc(me)}`));
      return list.map((p) => ({ id: p.id, name: p.name, active: p.active === 1 || p.active === "1", protocols: Object.keys(p).filter((k) => k.endsWith("_access") && String(p[k]) === "1").map((k) => k.replace("_access", "")), created: p.created }));
    });

    if (write) {
      t("create_my_app_password", "Create an app password for your mailbox (for a phone or desktop mail app). Returns the generated password once - tell the user to store it.",
        { name: z.string().min(1).max(60).describe("Label, e.g. 'iPhone Mail'") }, W, async ({ name }) => {
          const pw = Array.from(crypto.getRandomValues(new Uint8Array(18)), (b) => "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"[b % 57]).join("");
          await post("add/app-passwd", { username: me, app_name: name, app_passwd: pw, app_passwd2: pw, active: 1 });
          return { created: true, name, app_password: pw, note: "Shown only once." };
        });

      t("delete_my_app_password", "Delete one of your app passwords by id (from my_app_passwords).",
        { id: z.number().int(), confirm: z.boolean().optional() }, D, async ({ id, confirm }) => {
          needConfirm(confirm, "deletes this app password; any app using it stops working");
          const mine = asArray(await get(`get/app-passwd/all/${enc(me)}`)).map((p) => Number(p.id));
          if (!mine.includes(Number(id))) throw new Error("That app password does not belong to your mailbox.");
          await post("delete/app-passwd", [String(id)]);
          return { deleted: true, id };
        });

      t("release_my_quarantine_item", "Release a quarantined message to your inbox, or delete it. Only works on your own quarantine items.",
        { id: z.number().int(), action: z.enum(["release", "delete"]).default("release") }, W, async ({ id, action }) => {
          const mine = asArray(await get("get/quarantine/all")).filter((q) => String(q.rcpt || "").toLowerCase() === me).map((q) => Number(q.id));
          if (!mine.includes(Number(id))) throw new Error("That quarantine item is not addressed to you.");
          if (action === "delete") await post("delete/qitem", [String(id)]);
          else await post("edit/qitem", { items: [String(id)], attr: { action: "release" } });
          return { done: true, id, action };
        });
    }
  }

  if (!isAdmin) return;

  // ---------- Admin: system ----------
  t("server_status", "Mail server health: Mailcow version, container status and mail storage usage. Also confirms the API key works.", {}, RO, async () => {
    const [version, containers, vmail] = await Promise.all([
      get("get/status/version").catch((e) => ({ error: e.message })),
      get("get/status/containers").catch((e) => ({ error: e.message })),
      get("get/status/vmail").catch((e) => ({ error: e.message })),
    ]);
    const c = containers && !containers.error
      ? Object.values(containers).map((x) => ({ name: x.container, state: x.state, started: x.started_at }))
      : containers;
    const down = Array.isArray(c) ? c.filter((x) => x.state !== "running").map((x) => x.name) : [];
    return { version: version?.version ?? version, containers_running: Array.isArray(c) ? c.length - down.length : null, containers_not_running: down, containers: c, storage: vmail };
  });

  t("get_logs", `Read recent mail server logs. Types: ${LOG_TYPES.join(", ")}. Optional text filter.`,
    { type: z.enum(LOG_TYPES), count: z.number().int().min(1).max(500).default(50), contains: z.string().optional().describe("Only lines containing this text (case-insensitive)") },
    RO, async ({ type, count, contains }) => {
      let rows = asArray(await get(`get/logs/${type}/${count}`));
      if (contains) { const n = contains.toLowerCase(); rows = rows.filter((r) => JSON.stringify(r).toLowerCase().includes(n)); }
      return rows;
    });

  // ---------- Admin: domains ----------
  t("list_domains", "List mail domains with mailbox/alias counts and quota usage.", {}, RO, async () => asArray(await get("get/domain/all")).map(domainView));

  t("get_domain", "Full details of one domain.", { domain: z.string() }, RO, async ({ domain }) => {
    const d = await get(`get/domain/${enc(domain)}`);
    if (!d || !d.domain_name) throw new Error(`Domain ${domain} not found.`);
    return d;
  });

  // ---------- Admin: mailboxes ----------
  t("list_mailboxes", "List mailboxes, optionally for one domain, with quota usage and last login.",
    { domain: z.string().optional() }, RO, async ({ domain }) =>
      asArray(await get(domain ? `get/mailbox/all/${enc(domain)}` : "get/mailbox/all")).map(mailboxView));

  t("get_mailbox", "Full details of one mailbox.", { address: z.string().email() }, RO, async ({ address }) => {
    const m = await get(`get/mailbox/${enc(address)}`);
    if (!m || !m.username) throw new Error(`Mailbox ${address} not found.`);
    return m;
  });

  // ---------- Admin: aliases ----------
  t("list_aliases", "List aliases (forwarding addresses), optionally filtered by domain.", { domain: z.string().optional() }, RO, async ({ domain }) => {
    const all = asArray(await get("get/alias/all")).map(aliasView);
    return domain ? all.filter((a) => a.domain === domain) : all;
  });

  // ---------- Admin: queue ----------
  t("list_mail_queue", "List messages waiting in the outgoing mail queue (deferred / held / active). Use to check whether an email was delivered.",
    { sender: z.string().optional(), recipient: z.string().optional() }, RO, async ({ sender, recipient }) => {
      let q = asArray(await get("get/mailq/all")).map(queueView);
      if (sender) q = q.filter((x) => String(x.sender || "").toLowerCase().includes(sender.toLowerCase()));
      if (recipient) q = q.filter((x) => JSON.stringify(x.recipients || "").toLowerCase().includes(recipient.toLowerCase()));
      return { count: q.length, items: q };
    });

  // ---------- Admin: sync jobs ----------
  t("list_sync_jobs", "List IMAP sync/migration jobs with their last run result.", {}, RO, async () => asArray(await get("get/syncjobs/all/no_log")).map(syncView));

  // ---------- Admin: DKIM / quarantine / app passwords ----------
  t("get_dkim", "Show the DKIM key and the DNS TXT record to publish for a domain.", { domain: z.string() }, RO, async ({ domain }) => {
    const d = await get(`get/dkim/${enc(domain)}`);
    if (!d || !d.dkim_txt) return { domain, dkim: null, note: "No DKIM key for this domain. Use create_dkim." };
    return { domain, selector: d.dkim_selector, length: d.length, dns_record_name: `${d.dkim_selector}._domainkey.${domain}`, dns_txt_value: d.dkim_txt };
  });

  t("list_quarantine", "List spam-quarantined messages for all mailboxes.", { recipient: z.string().optional() }, RO, async ({ recipient }) => {
    const all = asArray(await get("get/quarantine/all")).map(quarantineView);
    return recipient ? all.filter((q) => String(q.recipient || "").toLowerCase() === recipient.toLowerCase()) : all;
  });

  if (!write) return;

  // ---------- Admin write tools ----------
  t("create_domain", "Create a new mail domain.",
    {
      domain: z.string(), description: z.string().optional(),
      max_mailboxes: z.number().int().default(10), max_aliases: z.number().int().default(400),
      domain_quota_mb: z.number().int().default(10240), default_mailbox_quota_mb: z.number().int().default(3072), max_mailbox_quota_mb: z.number().int().default(10240),
      active: z.boolean().default(true),
    }, W, async (a) => {
      await post("add/domain", clean({
        domain: a.domain, description: a.description, mailboxes: a.max_mailboxes, aliases: a.max_aliases,
        quota: a.domain_quota_mb, defquota: a.default_mailbox_quota_mb, maxquota: a.max_mailbox_quota_mb, active: bool(a.active), restart_sogo: 1,
      }));
      return { created: true, domain: a.domain, next: "Publish MX/SPF/DMARC records, then run create_dkim and publish the DKIM record." };
    });

  t("update_domain", "Change a domain's settings (description, limits, quotas, active).",
    {
      domain: z.string(), description: z.string().optional(), max_mailboxes: z.number().int().optional(), max_aliases: z.number().int().optional(),
      domain_quota_mb: z.number().int().optional(), default_mailbox_quota_mb: z.number().int().optional(), max_mailbox_quota_mb: z.number().int().optional(), active: z.boolean().optional(),
    }, W, async (a) => {
      const attr = clean({ description: a.description, mailboxes: a.max_mailboxes, aliases: a.max_aliases, quota: a.domain_quota_mb, defquota: a.default_mailbox_quota_mb, maxquota: a.max_mailbox_quota_mb, active: bool(a.active) });
      if (!Object.keys(attr).length) throw new Error("Nothing to change.");
      await post("edit/domain", { items: [a.domain], attr });
      return { updated: true, domain: a.domain, changed: Object.keys(attr) };
    });

  t("delete_domain", "Permanently delete a domain. Mailcow refuses if it still has mailboxes or aliases.",
    { domain: z.string(), confirm: z.boolean().optional() }, D, async ({ domain, confirm }) => {
      needConfirm(confirm, `deletes the domain ${domain}`);
      await post("delete/domain", [domain]);
      return { deleted: true, domain };
    });

  t("create_mailbox", "Create a mailbox. If no password is given a strong one is generated and returned once.",
    {
      address: z.string().email(), name: z.string().optional(), password: z.string().min(8).optional(),
      quota_mb: z.number().int().optional().describe("0 = unlimited (within domain limits); default = domain default"),
      force_password_change: z.boolean().default(false), active: z.boolean().default(true),
    }, W, async (a) => {
      const [local_part, domain] = a.address.split("@");
      const pw = a.password || Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"[b % 57]).join("");
      await post("add/mailbox", clean({ local_part, domain, name: a.name || local_part, password: pw, password2: pw, quota: a.quota_mb, force_pw_update: bool(a.force_password_change), active: bool(a.active) }));
      return { created: true, address: a.address, ...(a.password ? {} : { generated_password: pw, note: "Shown only once." }) };
    });

  t("update_mailbox", "Change a mailbox: display name, quota, password, active, or force a password change at next login.",
    { address: z.string().email(), name: z.string().optional(), quota_mb: z.number().int().optional(), password: z.string().min(8).optional(), active: z.boolean().optional(), force_password_change: z.boolean().optional() },
    W, async (a) => {
      const attr = clean({ name: a.name, quota: a.quota_mb, active: bool(a.active), force_pw_update: bool(a.force_password_change), ...(a.password ? { password: a.password, password2: a.password } : {}) });
      if (!Object.keys(attr).length) throw new Error("Nothing to change.");
      await post("edit/mailbox", { items: [a.address], attr });
      return { updated: true, address: a.address, changed: Object.keys(attr).filter((k) => k !== "password2") };
    });

  t("delete_mailbox", "Permanently delete a mailbox AND all of its email.",
    { address: z.string().email(), confirm: z.boolean().optional() }, D, async ({ address, confirm }) => {
      needConfirm(confirm, `deletes the mailbox ${address} and all its email`);
      await post("delete/mailbox", [address]);
      return { deleted: true, address };
    });

  t("create_alias", "Create an alias that forwards an address to one or more destinations.",
    { address: z.string().describe("Alias address, or @domain for a catch-all"), goto: z.string().describe("Comma-separated destination addresses"), active: z.boolean().default(true), comment: z.string().optional() },
    W, async (a) => {
      await post("add/alias", clean({ address: a.address, goto: a.goto, active: bool(a.active), public_comment: a.comment }));
      return { created: true, address: a.address, goto: a.goto };
    });

  t("update_alias", "Change an alias's destinations or active state (id from list_aliases).",
    { id: z.number().int(), goto: z.string().optional(), active: z.boolean().optional() }, W, async (a) => {
      const attr = clean({ goto: a.goto, active: bool(a.active) });
      if (!Object.keys(attr).length) throw new Error("Nothing to change.");
      await post("edit/alias", { items: [String(a.id)], attr });
      return { updated: true, id: a.id };
    });

  t("delete_alias", "Delete an alias by id (from list_aliases).", { id: z.number().int(), confirm: z.boolean().optional() }, D, async ({ id, confirm }) => {
    needConfirm(confirm, "deletes this alias");
    await post("delete/alias", [String(id)]);
    return { deleted: true, id };
  });

  t("manage_mail_queue", "Act on the outgoing mail queue: flush (retry all now), or deliver / hold / release specific queue ids.",
    { action: z.enum(["flush", "deliver", "hold", "release"]), queue_ids: z.array(z.string()).optional().describe("Required for deliver/hold/release") },
    W, async ({ action, queue_ids }) => {
      if (action === "flush") { await post("edit/mailq", { action: "flush" }); return { done: true, action }; }
      if (!queue_ids?.length) throw new Error("queue_ids is required for this action.");
      await post("edit/mailq", { items: queue_ids, action: action === "release" ? "unhold" : action });
      return { done: true, action, queue_ids };
    });

  t("delete_queue_items", "Permanently delete messages from the mail queue (they will never be delivered). Pass queue_ids, or all: true to empty the whole queue.",
    { queue_ids: z.array(z.string()).optional(), all: z.boolean().optional(), confirm: z.boolean().optional() }, D, async ({ queue_ids, all, confirm }) => {
      if (!all && !queue_ids?.length) throw new Error("Give queue_ids, or all: true.");
      needConfirm(confirm, all ? "deletes EVERY message in the mail queue" : `deletes ${queue_ids.length} queued message(s)`);
      if (all) await post("delete/mailq", { action: "super_delete" });
      else await post("delete/mailq", { items: queue_ids });
      return { deleted: true, ...(all ? { all: true } : { queue_ids }) };
    });

  t("create_sync_job", "Create an IMAP sync job that copies mail from another server into a local mailbox (migration).",
    {
      mailbox: z.string().email().describe("Local destination mailbox"), source_host: z.string(), source_port: z.number().int().default(993),
      source_user: z.string(), source_password: z.string(), encryption: z.enum(["SSL", "TLS", "PLAIN"]).default("SSL"),
      interval_min: z.number().int().default(20), target_subfolder: z.string().default("External"), delete_from_source: z.boolean().default(false), active: z.boolean().default(true),
    }, W, async (a) => {
      await post("add/syncjob", {
        username: a.mailbox, host1: a.source_host, port1: a.source_port, user1: a.source_user, password1: a.source_password, enc1: a.encryption,
        mins_interval: a.interval_min, subfolder2: a.target_subfolder, delete1: bool(a.delete_from_source), automap: 1, skipcrossduplicates: 0, subscribeall: 1,
        maxage: 0, maxbytespersecond: 0, timeout1: 600, timeout2: 600, exclude: "(?i)spam|(?i)junk", custom_params: "", delete2duplicates: 1, delete2: 0, active: bool(a.active),
      });
      return { created: true, mailbox: a.mailbox, source: `${a.source_user}@${a.source_host}` };
    });

  t("update_sync_job", "Activate, deactivate or change the interval of a sync job (id from list_sync_jobs).",
    { id: z.number().int(), active: z.boolean().optional(), interval_min: z.number().int().optional() }, W, async (a) => {
      const attr = clean({ active: bool(a.active), mins_interval: a.interval_min });
      if (!Object.keys(attr).length) throw new Error("Nothing to change.");
      await post("edit/syncjob", { items: [String(a.id)], attr });
      return { updated: true, id: a.id };
    });

  t("delete_sync_job", "Delete a sync job (already copied mail stays).", { id: z.number().int(), confirm: z.boolean().optional() }, D, async ({ id, confirm }) => {
    needConfirm(confirm, "deletes this sync job");
    await post("delete/syncjob", [String(id)]);
    return { deleted: true, id };
  });

  t("create_dkim", "Generate a DKIM key for a domain and return the DNS record to publish.",
    { domain: z.string(), selector: z.string().default("dkim"), key_size: z.enum(["1024", "2048", "3072", "4096"]).default("2048") }, W, async (a) => {
      await post("add/dkim", { domains: a.domain, dkim_selector: a.selector, key_size: Number(a.key_size) });
      const d = await get(`get/dkim/${enc(a.domain)}`);
      return { created: true, domain: a.domain, dns_record_name: `${a.selector}._domainkey.${a.domain}`, dns_txt_value: d?.dkim_txt };
    });

  t("delete_quarantine_item", "Permanently delete a quarantined message (id from list_quarantine).", { id: z.number().int(), confirm: z.boolean().optional() }, D, async ({ id, confirm }) => {
    needConfirm(confirm, "deletes this quarantined message");
    await post("delete/qitem", [String(id)]);
    return { deleted: true, id };
  });
}
