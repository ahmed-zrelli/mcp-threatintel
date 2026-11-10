#!/usr/bin/env bash
# mcp-threatintel v2 — install on the protected Ubuntu server (24.04).
#
#   sudo ANALYST_IP=192.168.21.1 bash scripts/ubuntu/setup-ubuntu.sh
#
# Run from the project directory. Safe to re-run: existing tokens and
# /etc/threatintel/responder.env are kept; the firewall table, the allowlist,
# the agent and the containers are refreshed.
#
#   ANALYST_IP  IP of the analyst PC (only host allowed on :3707, always
#               allowlisted). Default: the IP of the current SSH client.
#   LAB_USER    user who approves actions and owns the lab folder (default: SUDO_USER)
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB_USER="${LAB_USER:-${SUDO_USER:-}}"
[[ -n "$LAB_USER" && "$LAB_USER" != root ]] || { echo "set LAB_USER (the analyst's login)" >&2; exit 1; }
LAB_HOME="$(getent passwd "$LAB_USER" | cut -d: -f6)"
ANALYST_IP="${ANALYST_IP:-$(echo "${SSH_CLIENT:-}" | awk '{print $1}')}"
[[ "$ANALYST_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "set ANALYST_IP=<your PC's IP>" >&2; exit 1; }

ETC=/etc/threatintel
VAR=/var/lib/threatintel
OPT=/opt/threatintel
step() { printf '\n==> %s\n' "$*"; }
token() { python3 -c 'import secrets; print(secrets.token_hex(32))'; }

step "packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nftables python3-venv python3-pip >/dev/null
if ! command -v docker >/dev/null; then
  apt-get install -y -qq docker.io >/dev/null
fi
if ! docker compose version >/dev/null 2>&1; then
  apt-get install -y -qq docker-compose-v2 >/dev/null 2>&1 || apt-get install -y -qq docker-compose-plugin >/dev/null
fi
systemctl enable --now docker >/dev/null

step "groups (threatintel = MCP container, threatintel-admin = analyst)"
getent group threatintel >/dev/null || groupadd --system threatintel
getent group threatintel-admin >/dev/null || groupadd --system threatintel-admin
usermod -aG threatintel-admin "$LAB_USER"
GID_AGENT="$(getent group threatintel | cut -d: -f3)"

step "directories"
install -d -m 0755 -o root -g root "$VAR"
install -d -m 0750 -o 1000 -g 1000 "$VAR/data"                 # SQLite cache, written by the containers (UID 1000)
install -d -m 0700 -o root -g root "$VAR/responder"            # responder.db, quarantine, hosts backup
install -d -m 0750 -o root -g threatintel-admin "$ETC"
install -d -m 0755 -o "$LAB_USER" -g "$LAB_USER" "$LAB_HOME/threatintel-lab"

step "secrets"
if [[ ! -f "$ETC/admin.token" ]]; then
  token > "$ETC/admin.token"
fi
chown root:threatintel-admin "$ETC/admin.token"; chmod 0640 "$ETC/admin.token"

if [[ ! -f "$ETC/responder.env" ]]; then
  cat > "$ETC/responder.env" <<EOF
# threatintel-responder (systemd EnvironmentFile). Change RESPONDER_DRY_RUN to
# false and run: sudo systemctl restart threatintel-responder
AGENT_TOKEN=$(token)
AGENT_ADDR=unix:///run/threatintel/agent.sock
ADMIN_ADDR=unix:///run/threatintel-admin/admin.sock
ADMIN_TOKEN_FILE=$ETC/admin.token
AGENT_SOCKET_GROUP=threatintel
ADMIN_SOCKET_GROUP=threatintel-admin
RESPONDER_DATA_DIR=$VAR/responder
DB_PATH=$VAR/data/threatintel.db
NFT_RULESET_FILE=$ETC/threatintel.nft
ALLOWLIST_FILE=$ETC/allowlist.csv
SCAN_PATHS=$LAB_HOME/threatintel-lab
RESPONDER_DRY_RUN=true
BLOCK_DEFAULT_TTL=24
BLOCK_TTL_UNIT=hours
AUTH_FAIL_THRESHOLD=5
EOF
fi
chown root:root "$ETC/responder.env"; chmod 0600 "$ETC/responder.env"
AGENT_TOKEN="$(grep -E '^AGENT_TOKEN=' "$ETC/responder.env" | cut -d= -f2-)"

step "allowlist (analyst PC $ANALYST_IP as a single /32)"
{
  echo "value,type,comment"
  echo "$ANALYST_IP/32,cidr,analyst PC (MCP client, SSH)"
  grep -vE '^\s*(#|$|value,)' "$PROJECT_DIR/lab/allowlist.csv" || true
} > "$ETC/allowlist.csv"
chmod 0644 "$ETC/allowlist.csv"

step "nftables table inet threatintel"
sed "s/@MCP_CLIENTS@/$ANALYST_IP/" "$PROJECT_DIR/deploy/threatintel.nft" > "$ETC/threatintel.nft"
chmod 0644 "$ETC/threatintel.nft"
nft -c -f "$ETC/threatintel.nft"        # syntax check before loading
nft -f "$ETC/threatintel.nft"

step "host agent in $OPT/venv"
python3 -m venv "$OPT/venv"
"$OPT/venv/bin/pip" install -q --upgrade pip
"$OPT/venv/bin/pip" install -q "$PROJECT_DIR"
ln -sf "$OPT/venv/bin/threatintel-approve" /usr/local/bin/threatintel-approve
install -m 0644 "$PROJECT_DIR/deploy/threatintel-responder.service" /etc/systemd/system/threatintel-responder.service
systemctl daemon-reload
systemctl enable threatintel-responder >/dev/null
systemctl restart threatintel-responder

step "lab test files in $LAB_HOME/threatintel-lab"
sudo -u "$LAB_USER" python3 "$PROJECT_DIR/lab/create_test_files.py" "$LAB_HOME/threatintel-lab" | tail -1

step "containers (.env for docker compose)"
ENV_FILE="$PROJECT_DIR/.env"
touch "$ENV_FILE"
setenv() {  # replace or append KEY=VALUE in the compose .env
  if grep -qE "^$1=" "$ENV_FILE"; then sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"; else echo "$1=$2" >> "$ENV_FILE"; fi
}
setenv AGENT_TOKEN "$AGENT_TOKEN"
setenv AGENT_ADDR unix:///run/threatintel/agent.sock
setenv ADMIN_ADDR unix:///run/threatintel-admin/admin.sock
setenv ADMIN_TOKEN_FILE "$ETC/admin.token"
setenv THREATINTEL_GID "$GID_AGENT"
setenv DB_PATH /data/threatintel.db
setenv LOCAL_IOCS_FILE /app/lab/local_iocs.csv
setenv MCP_LOG_FORMAT text
grep -qE '^CORS_ORIGINS=' "$ENV_FILE" || setenv CORS_ORIGINS http://localhost:8080,http://127.0.0.1:8080
chown "$LAB_USER":"$LAB_USER" "$ENV_FILE"; chmod 0600 "$ENV_FILE"
grep -qE '^ABUSECH_API_KEY=.+' "$ENV_FILE" && ! grep -q 'your_abusech' "$ENV_FILE" \
  || echo "WARNING: ABUSECH_API_KEY is not set in $ENV_FILE (feeds will not sync)"
cd "$PROJECT_DIR"
docker compose build -q
docker compose up -d

step "status"
sleep 3
systemctl --no-pager --lines=5 status threatintel-responder | sed -n '1,8p'
docker compose ps
VM_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
cat <<EOF

Done.
  MCP server (from the analyst PC only): http://$VM_IP:3707/mcp
  Agent mode: $(grep -E '^RESPONDER_DRY_RUN=' "$ETC/responder.env")
  Approve actions (log in again first so the threatintel-admin group applies):
      threatintel-approve list
  Real mode: set RESPONDER_DRY_RUN=false in $ETC/responder.env, then
      sudo systemctl restart threatintel-responder
EOF
