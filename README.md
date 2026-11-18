# mailcow-mcp-server

A remote [MCP](https://modelcontextprotocol.io) server for managing a **[Mailcow](https://mailcow.email)** mail server from AI assistants such as **Claude**.

You can ask *"create a mailbox for sara@example.com with 5 GB"*, *"why is mail to gmail stuck in the queue?"* or *"give me the DKIM record for example.com"*, and the server does it through the Mailcow API.

```
Claude ──HTTPS──▶ reverse proxy ──▶ mailcow-mcp-server :3901 ──Mailcow API──▶ Mailcow
                                   │
                                   └─ sign-in page: mailbox email + password (IMAP login)
```

> To read and send email instead of administering the server, see the companion project **[mailbox-mcp-server](https://github.com/mustafa-mph/mailbox-mcp-server)**.

## How access works

- **Sign-in.** Users connect the URL in Claude and sign in with their Mailcow mailbox email and password. The password is checked with an IMAP login against your Mailcow server.
- **Admins.** Addresses listed in `ADMIN_EMAILS` get the admin tools.
- **Everyone else.** Other users get **self-service** tools that only ever see or change their own mailbox. Set `ADMINS_ONLY=true` to stop non-admins signing in at all.
- **Optional static token.** `MCP_AUTH_TOKEN` gives admin access to headless clients and scripts.
- **The API key never leaves the server.** Users never see it, and ownership is checked in this server's code before any API call is made.

## Tools

### Admin

| Area | Tools |
|---|---|
| System | `server_status` (version, containers, storage, API check), `get_logs` (postfix, dovecot, rspamd-history, sogo, netfilter, acme, api, ...) |
| Domains | `list_domains`, `get_domain`, `create_domain`, `update_domain`, `delete_domain` |
| Mailboxes | `list_mailboxes`, `get_mailbox`, `create_mailbox`, `update_mailbox`, `delete_mailbox` |
| Aliases | `list_aliases`, `create_alias`, `update_alias`, `delete_alias` |
| Mail queue | `list_mail_queue`, `manage_mail_queue` (flush / deliver / hold / release), `delete_queue_items` |
| Sync jobs | `list_sync_jobs`, `create_sync_job`, `update_sync_job`, `delete_sync_job` |
| DKIM | `get_dkim`, `create_dkim` (both return the DNS record to publish) |
| Quarantine | `list_quarantine`, `delete_quarantine_item` |

### Self-service (every signed-in user)

| Tool | What it does |
|---|---|
| `my_account` | Quota, space used, message count, last login |
| `my_aliases` | Aliases that deliver to me |
| `my_quarantine` / `release_my_quarantine_item` | See spam held for me; release it to the inbox, or delete it |
| `my_app_passwords` / `create_my_app_password` / `delete_my_app_password` | Manage app passwords for phone and desktop mail apps |

### Safety

- **Deletes need confirmation.** Every delete tool refuses to run until it's called again with `confirm: true`, and carries the MCP `destructiveHint` annotation, so clients ask the user first.
- **Read-only mode.** `MAILCOW_API_ACCESS=read-only` (use it with a read-only Mailcow API key) hides every tool that changes something.
- **Readable errors.** Mailcow error messages (for example `mailbox_invalid`) are passed back to the assistant as they are.

## Quick start (Docker)

1. **Create a Mailcow API key.** In Mailcow, go to **System → Configuration → Access → API**. Create a read-write (or read-only) key and add the IP address of the machine running this server.
2. **Configure and start the server:**
   ```bash
   git clone https://github.com/mustafa-mph/mailcow-mcp-server.git
   cd mailcow-mcp-server
   cp .env.example .env
   # edit .env: MAILCOW_API_URL, MAILCOW_API_KEY, PUBLIC_BASE_URL, SESSION_SECRET, ADMIN_EMAILS
   docker compose up -d --build
   curl http://127.0.0.1:3901/healthz   # -> ok
   ```
3. **Put HTTPS in front.** Example for Caddy:
   ```caddyfile
   mcp-admin.example.com {
       reverse_proxy 127.0.0.1:3901
   }
   ```
4. **Connect from Claude.** Open **Settings → Connectors → Add custom connector**, enter `https://mcp-admin.example.com`, click **Connect** and sign in with your mailbox.

Without Docker, run `npm install` and then `SESSION_FILE=./data/sessions.json npm start`. Node.js 20 or newer is required.

## Configuration

| Variable | Required | Description |
|---|---|---|
| `MAILCOW_API_URL` | yes | Base URL of your Mailcow, e.g. `https://mail.example.com` |
| `MAILCOW_API_KEY` | yes | Mailcow API key |
| `MAILCOW_API_ACCESS` | | `read-write` (default) or `read-only` |
| `PUBLIC_BASE_URL` | yes | Public HTTPS URL of this server |
| `SESSION_SECRET` | yes | 32+ random characters; encrypts saved sign-ins |
| `ADMIN_EMAILS` | | Comma list of mailboxes that get the admin tools |
| `ADMINS_ONLY` | | `true` = only admins may sign in |
| `USER_MAIL_DOMAIN` | | Only allow `@this-domain` addresses to sign in |
| `MCP_AUTH_TOKEN` | | Static admin bearer token for headless clients |
| `USER_IMAP_HOST` / `USER_IMAP_PORT` | | IMAP server used to check passwords (default: Mailcow host, port 993) |
| `BRAND_NAME` | | Name shown on the sign-in page |
| `PORT`, `SESSION_FILE`, `TRUST_PROXY_HOPS`, `MAILCOW_API_TIMEOUT_MS` | | Advanced settings |

## Security notes

- **The Mailcow API key has full control of your mail server.** Keep `.env` private, and in Mailcow restrict the key to this server's IP.
- **Saved sign-ins.** They are AES-256-GCM encrypted in `data/sessions.json`. Access tokens are stored only as hashes and expire after 90 days.
- **Brute-force protection.** 5 failed sign-ins per IP address lock that IP out for 10 minutes.
- **Only run it behind HTTPS.**

## Files

```
index.js     HTTP server, sign-in routing, admin vs self-service
mailcow.js   Mailcow API client and all tools
oauth.js     OAuth 2.1 endpoints (dynamic registration + PKCE), sign-in page, encrypted session store
```

## License

[MIT](LICENSE)
