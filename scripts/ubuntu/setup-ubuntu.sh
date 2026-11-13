#!/usr/bin/env bash
# mcp-threatintel v2 — install the HOST AGENT on the protected Ubuntu server (24.04).
#
#   sudo ANALYST_IP=192.168.21.1 bash scripts/ubuntu/setup-ubuntu.sh
#
# Architecture: the server runs ONLY the agent (detection + response, systemd).
# The console (MCP server for Qwen, feed poller, dashboard) runs on the analyst
# PC and reaches the agent over TLS on 3712 (agent channel) and 3713 (admin
# channel); nftables lets only ANALYST_IP reach those ports.
#
# Run from the project directory. Safe to re-run: tokens, the TLS certificate
# and /etc/threatintel/responder.env are kept; the firewall table, the
# allowlist and the agent are refreshed.
#
#   ANALYST_IP       IP of the analyst PC (only host allowed on the agent ports, always
#                    allowlisted). Default: the IP of the current SSH client.
#   LAB_USER         analyst's login on this server (default: SUDO_USER); never locked by lock_user
#   WITH_CONTAINERS  1 = also run the old all-on-the-server containers (MCP server + poller)
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB_USER="${LAB_USER:-${SUDO_USER:-}}"
[[ -n "$LAB_USER" && "$LAB_USER" != root ]] || { echo "set LAB_USER (the analyst's login)" >&2; exit 1; }
LAB_HOME="$(getent passwd "$LAB_USER" | cut -d: -f6)"
ANALYST_IP="${ANALYST_IP:-$(echo "${SSH_CLIENT:-}" | awk '{print $1}')}"
[[ "$ANALYST_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "set ANALYST_IP=<your PC's IP>" >&2; exit 1; }
WITH_CONTAINERS="${WITH_CONTAINERS:-0}"

ETC=/etc/threatintel
VAR=/var/lib/threatintel
OPT=/opt/threatintel
CONSOLE="$ETC/console"     # what the analyst copies to the PC (readable by threatintel-admin)
VM_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
step() { printf '\n==> %s\n' "$*"; }
token() { python3 -c 'import secrets; print(secrets.token_hex(32))'; }
setkey() {  # replace or append KEY=VALUE in responder.env
  if grep -qE "^$1=" "$ETC/responder.env"; then sed -i "s|^$1=.*|$1=$2|" "$ETC/responder.env"
  else echo "$1=$2" >> "$ETC/responder.env"; fi
}

step "packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nftables python3-venv python3-pip openssl >/dev/null

step "groups (threatintel = local agent socket, threatintel-admin = analyst)"
getent group threatintel >/dev/null || groupadd --system threatintel
getent group threatintel-admin >/dev/null || groupadd --system threatintel-admin
usermod -aG threatintel-admin "$LAB_USER"

step "directories"
install -d -m 0755 -o root -g root "$VAR"
install -d -m 0750 -o 1000 -g 1000 "$VAR/data"                 # threat-intel snapshot pushed by the console
install -d -m 0700 -o root -g root "$VAR/responder"            # responder.db, quarantine, hosts backup
install -d -m 0750 -o root -g threatintel-admin "$ETC"
install -d -m 0750 -o root -g threatintel-admin "$CONSOLE"
install -d -m 0755 -o "$LAB_USER" -g "$LAB_USER" "$LAB_HOME/threatintel-lab"

step "secrets"
[[ -f "$ETC/admin.token" ]] || token > "$ETC/admin.token"
chown root:threatintel-admin "$ETC/admin.token"; chmod 0640 "$ETC/admin.token"

if [[ ! -f "$ETC/responder.env" ]]; then
  cat > "$ETC/responder.env" <<EOF
# threatintel-responder (systemd EnvironmentFile). Change RESPONDER_DRY_RUN to
# false and run: sudo systemctl restart threatintel-responder
AGENT_TOKEN=$(token)
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
# Network channels for the console on the analyst PC (TLS), plus the local sockets.
setkey AGENT_ADDR "tls://0.0.0.0:3712,unix:///run/threatintel/agent.sock"
setkey ADMIN_ADDR "tls://0.0.0.0:3713,unix:///run/threatintel-admin/admin.sock"
setkey TLS_CERT "$ETC/agent.crt"
setkey TLS_KEY "$ETC/agent.key"
setkey ALLOWED_CLIENTS "$ANALYST_IP"
# lock_user must never lock the analyst out
grep -q '^PROTECTED_USERS=' "$ETC/responder.env" || setkey PROTECTED_USERS "root,$LAB_USER"
chown root:root "$ETC/responder.env"; chmod 0600 "$ETC/responder.env"
AGENT_TOKEN="$(grep -E '^AGENT_TOKEN=' "$ETC/responder.env" | cut -d= -f2-)"

step "TLS certificate of the agent (self-signed, pinned by the console)"
if [[ ! -f "$ETC/agent.crt" ]]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 \
    -subj "/CN=threatintel-agent" -addext "subjectAltName=IP:${VM_IP:-127.0.0.1},IP:127.0.0.1" \
    -keyout "$ETC/agent.key" -out "$ETC/agent.crt" 2>/dev/null
fi
chown root:root "$ETC/agent.key"; chmod 0600 "$ETC/agent.key"
chmod 0644 "$ETC/agent.crt"

step "console bundle in $CONSOLE (copy it to the analyst PC)"
install -m 0640 -o root -g threatintel-admin "$ETC/agent.crt" "$CONSOLE/agent.crt"
install -m 0640 -o root -g threatintel-admin "$ETC/admin.token" "$CONSOLE/admin.token"
printf '%s\n' "$AGENT_TOKEN" > "$CONSOLE/agent.token"
chown root:threatintel-admin "$CONSOLE/agent.token"; chmod 0640 "$CONSOLE/agent.token"
cat > "$CONSOLE/console.env" <<EOF
# Console settings for the analyst PC (merge into the project's .env there)
AGENT_ADDR=tls://$VM_IP:3712
PUSH_AGENT_ADDR=tls://$VM_IP:3712
ADMIN_ADDR=tls://$VM_IP:3713
AGENT_CA=console/agent.crt
ADMIN_TOKEN_FILE=console/admin.token
EOF
chown root:threatintel-admin "$CONSOLE/console.env"; chmod 0640 "$CONSOLE/console.env"

step "allowlist (analyst PC $ANALYST_IP as a single /32)"
{
  echo "value,type,comment"
  echo "$ANALYST_IP/32,cidr,analyst PC (console)"
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

if [[ "$WITH_CONTAINERS" == 1 ]]; then
  step "containers (optional all-on-the-server mode)"
  command -v docker >/dev/null || apt-get install -y -qq docker.io >/dev/null
  docker compose version >/dev/null 2>&1 || apt-get install -y -qq docker-compose-v2 >/dev/null
  ENV_FILE="$PROJECT_DIR/.env"; touch "$ENV_FILE"
  setenv() { if grep -qE "^$1=" "$ENV_FILE"; then sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"; else echo "$1=$2" >> "$ENV_FILE"; fi; }
  setenv AGENT_TOKEN "$AGENT_TOKEN"
  setenv AGENT_ADDR unix:///run/threatintel/agent.sock
  setenv ADMIN_ADDR unix:///run/threatintel-admin/admin.sock
  setenv THREATINTEL_GID "$(getent group threatintel | cut -d: -f3)"
  setenv DB_PATH /data/threatintel.db
  setenv LOCAL_IOCS_FILE /app/lab/local_iocs.csv
  chown "$LAB_USER":"$LAB_USER" "$ENV_FILE"; chmod 0600 "$ENV_FILE"
  (cd "$PROJECT_DIR" && docker compose build -q && docker compose up -d)
elif command -v docker >/dev/null && [[ -n "$(cd "$PROJECT_DIR" && docker compose ps -q 2>/dev/null)" ]]; then
  echo "NOTE: old containers are still running; the console now runs on the PC. Stop them with:"
  echo "      cd $PROJECT_DIR && docker compose down"
fi

step "status"
sleep 3
systemctl --no-pager --lines=5 status threatintel-responder | sed -n '1,8p'
cat <<EOF

Done. This server now runs only the agent.
  Agent channel (TLS): $VM_IP:3712    Admin channel (TLS): $VM_IP:3713   (from $ANALYST_IP only)
  Agent mode: $(grep -E '^RESPONDER_DRY_RUN=' "$ETC/responder.env")
  Console bundle for the PC: $CONSOLE  (agent.crt, agent.token, admin.token, console.env)
  Real mode: set RESPONDER_DRY_RUN=false in $ETC/responder.env, then
      sudo systemctl restart threatintel-responder
EOF
