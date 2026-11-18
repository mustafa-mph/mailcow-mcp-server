#!/usr/bin/env bash
# Create or change an admin login for the sign-in page, then restart the server.
#   ./set-admin-password.sh <username>
# You type the password (hidden); only its scrypt hash is stored in .env.
set -euo pipefail
cd "$(dirname "$0")"
USER_NAME="${1:-}"
[ -n "$USER_NAME" ] || { echo "Usage: $0 <username>"; exit 1; }
SERVICE=$(docker compose config --services | head -1)
TMP="data/.admin-entry"
rm -f "$TMP"

docker compose run --rm -it --no-deps "$SERVICE" node hash-password.js "$USER_NAME" --out "/$TMP"
[ -s "$TMP" ] || { echo "No password set."; exit 1; }
ENTRY=$(cat "$TMP"); rm -f "$TMP"
NAME="${ENTRY%%:*}"

touch .env
CURRENT=$(grep -E '^ADMIN_USERS=' .env | head -1 | cut -d= -f2- || true)
# drop any existing entry for this user, keep the others
KEEP=$(echo "$CURRENT" | tr ',' '\n' | grep -v -i -E "^${NAME}:" | grep -v '^$' | paste -sd, - || true)
NEW="${KEEP:+$KEEP,}$ENTRY"
if grep -qE '^ADMIN_USERS=' .env; then
  grep -v -E '^ADMIN_USERS=' .env > .env.tmp && echo "ADMIN_USERS=$NEW" >> .env.tmp && cat .env.tmp > .env && rm -f .env.tmp
else
  echo "ADMIN_USERS=$NEW" >> .env
fi
chmod 600 .env
docker compose up -d >/dev/null 2>&1
echo "Admin login '$NAME' saved. Server restarted. Sign in at the connector with username '$NAME'."
