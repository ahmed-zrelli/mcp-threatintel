# mcp-threatintel v2 — split architecture (recommended)

The protected Ubuntu server runs **only the host agent**. Everything the analyst
uses runs on the analyst PC: the local model (Qwen via llama-server), the MCP
server that gives it its tools, the feed poller and the dashboard.

```
Analyst PC (Windows, 192.168.21.1)                         Ubuntu server (protected, 192.168.21.129)
  llama-server + WebUI ─HTTP 127.0.0.1:3707─▶ MCP server ─┐
  feed poller (abuse.ch, OTX, CISA) ── push intel ────────┼─TLS :3712 agent channel──▶ threatintel-responder
  dashboard 127.0.0.1:3720 ───────────────────────────────┴─TLS :3713 admin channel──▶ (systemd, root)
                                                                                         detection 24/7
                                                                                         nftables · /etc/hosts
                                                                                         quarantine · kill · lock_user
```

Why this split:
- The server keeps detecting and responding when the PC is off (detection is in the agent).
- A compromised server never holds the analyst's tools, the feed API keys or the model.
- Both channels are TLS with the agent's certificate **pinned** on the PC; each has its
  own token; nftables and the agent accept only the analyst PC.
- The agent channel (MCP server / Qwen, poller) can scan, propose actions and push intel.
  The server runs in **AI mode only**: the model decides and its actions are executed. The
  admin channel (dashboard, `threatintel-approve`) lets the analyst watch, cancel pending
  actions and roll back what the AI did.

## 1. Server (once)

```bash
cd ~/mcp-threatintel
sudo ANALYST_IP=192.168.21.1 bash scripts/ubuntu/setup-ubuntu.sh
docker compose down          # only if the old all-on-the-server containers still run
```

The script installs the agent (dry-run first), creates a self-signed certificate and
writes the **console bundle** to `/etc/threatintel/console/` (agent.crt, agent.token,
admin.token, console.env), readable by the analyst's account.

## 2. PC (once)

```powershell
mkdir console
scp -i <key> <user>@192.168.21.129:/etc/threatintel/console/* console\
```

`console\` is git-ignored: it holds the two tokens. Keep `ABUSECH_API_KEY` /
`OTX_API_KEY` in `.env` as before.

## 3. Start (each session, by hand)

1. llama-server (as before), WebUI on `http://localhost:8080`.
2. `powershell -ExecutionPolicy Bypass -File scripts\windows\start-console.ps1`
   opens three windows (MCP server, poller, dashboard) and the dashboard in the browser.
   Nothing is installed to start automatically.
3. WebUI → MCP server `http://127.0.0.1:3707/mcp`, system message from
   `docs/qwen-system-prompt.md`.

The first poller cycle pushes the intel database to the agent (dashboard header:
"intel updated ..."). `mcp-threatintel-poller --push-only` re-sends it at any time.

## 4. Daily use

- **Alerts appear on the dashboard** as soon as the agent detects something (feeds and
  behavior: port scans, reverse shells, new listening ports, account changes, system-file
  changes, SSH brute force, C2 connections, malicious DNS/files/processes).
- Rules propose actions instantly (pending, "Waiting for the AI"). When you ask Qwen to
  investigate, it decides: **every action it requests is executed** — block_ip,
  sinkhole_domain, quarantine_file, kill_process, lock_user (max `AUTONOMY_MAX_PER_HOUR`,
  default 20/hour). The server still refuses protected targets (allowlist, root, your
  account, system processes). You can Cancel a pending action or Rollback an executed one.
- **The AI never starts on its own.** To get an analysis, type in the WebUI:
  `Investigate alert 12`. The report is saved and shown on the dashboard.
- Active responses show their time left and a Rollback button.
- Report: dashboard → Incident report (or `threatintel-approve report --incident 3`).

## 5. Checks

```bash
# server
sudo systemctl status threatintel-responder
sudo journalctl -u threatintel-responder -f
sudo nft list table inet threatintel
sudo ss -ltnp | grep -E '3712|3713'
```

```powershell
# PC (in a window started by start-console.ps1, or with the same variables)
.venv\Scripts\threatintel-approve mode
.venv\Scripts\threatintel-approve incidents
```
