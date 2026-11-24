# mcp-threatintel v2: threat intelligence + autonomous response with a local LLM

A lightweight **SOAR** (Security Orchestration, Automation and Response) for a protected Ubuntu
server. A host agent detects attacks 24/7 from threat feeds and from behavior. Deterministic rules
answer the clear-cut cases at once. What the rules cannot judge is investigated and decided by a
**local language model** (Qwen via llama.cpp), which uses the tools of an **MCP server**. Every action
is validated, audited and reversible.

> Fork of [pete-builds/mcp-threatintel](https://github.com/pete-builds/mcp-threatintel), a threat
> intelligence MCP server for Claude Code. v2 adds host detection, response, the AI responder and
> the analyst dashboard.

---

## Architecture

```
Analyst PC (Windows)                                            Ubuntu server (protected)
                                                                ─────────────────────────
 llama-server + WebUI (Qwen, :8080)                             threatintel-responder
   │  HTTP 127.0.0.1:3707/mcp                                   (systemd, root, always on)
   ▼                                                              detection 24/7:
 MCP server (28 tools) ──────── TLS :3712  agent channel ──────▶   feeds: C2, DNS, files,
 AI responder (Qwen decides) ──┘                                   command lines, SSH
 feed poller (abuse.ch, OTX, CISA) ── push intel ──(:3712)──────▶   behavior: port scans,
 dashboard 127.0.0.1:3720 ─────── TLS :3713  admin channel ──────▶   reverse shells, new ports,
                                                                    accounts, system files,
                                                                    SSH brute force
                                                                  responses: nftables block,
                                                                    DNS sinkhole, quarantine,
                                                                    kill process, lock user
```

Why this split:

- **The server keeps protecting itself when the PC is off.** Detection and the rules live in the agent.
- **A compromised server never holds the analyst's tools,** the feed API keys or the model.
- **Both channels are TLS with the agent certificate pinned on the PC,** each with its own token.
  nftables and the agent accept only the analyst PC.

### Who decides

1. **Rules first.** Threat-feed matches (C2 connection, malicious DNS / file / command line), SSH
   brute force, port scans and reverse shells are blocked, killed or quarantined at once.
2. **AI next.** Unusual behavior (new listening port, account or system-file changes, suspicious
   command lines), a refused or failed rule action, or an attack that persists is queued for the
   **AI responder**. It runs Qwen on each alert in a fresh conversation. Qwen investigates with the
   MCP tools, writes a report, then decides with `resolve_alert`: execute, dismiss or escalate.
3. **The analyst keeps control.** The dashboard shows every alert, incident, decision and report. A
   pending action can be cancelled and an executed one rolled back. A "Who decides" switch toggles
   between AI and Human approval.

### Guardrails (enforced by the agent, whatever the model says)

- Validation of every action and its target.
- An allowlist: the analyst PC, the gateway, DNS and loopback can never be blocked.
- Protected accounts and processes: root and PID 1 are refused.
- An hourly limit on AI actions (`AUTONOMY_MAX_PER_HOUR`).
- No approve tool is exposed to the model.
- A full audit trail of who proposed, decided and executed each action, and when.
- Text from feeds, logs, file names and command lines is treated as data, never as instructions.

---

## MCP tools (28)

| Family | Tools |
|---|---|
| Threat intelligence | `lookup_ioc`, `search_threats`, `get_recent_threats`, `lookup_cve`, `get_feed_status`, `search_pulses`, `check_password_breach`, `get_latest_breach` |
| Host scans | `scan_network_connections`, `scan_files`, `check_auth_logs`, `scan_host` |
| Alerts and investigation | `list_alerts`, `list_incidents`, `investigate_host`, `related_iocs`, `resolve_alert`, `save_alert_report`, `incident_report` |
| Responses (executed after validation) | `block_ip`, `sinkhole_domain`, `quarantine_file`, `kill_process`, `lock_user`, `block_feed_c2` |
| Action queue | `list_actions`, `get_action_status`, `rollback_action` |

Tool results are compact JSON (no indentation, no empty fields, identical entries counted), which
saves about 30% of the model's context with no information lost. Set `MCP_COMPACT=0` for indented output.

### Data sources

| Source | Provides | Key |
|---|---|---|
| [abuse.ch](https://abuse.ch/) (URLhaus, MalwareBazaar, ThreatFox, Feodo) | Malware URLs, hashes, C2s, botnet IPs | `ABUSECH_API_KEY` (free, required) |
| [AlienVault OTX](https://otx.alienvault.com/) | Community threat pulses | `OTX_API_KEY` (free, optional) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerabilities | none |
| [HIBP Passwords](https://haveibeenpwned.com/Passwords) | Breached passwords (k-anonymity) | none |
| `lab/local_iocs.csv` | Lab indicators for the demo scenarios | none |

---

## Requirements

- **Server:** Ubuntu 22.04 or later (tested in a VMware VM), sudo, nftables.
- **Analyst PC:** Windows 10/11, Python 3.11 or later, OpenSSH client.
- **Local model:** [llama.cpp](https://github.com/ggml-org/llama.cpp) `llama-server` and a
  tool-calling model in GGUF format. Tested with `Qwen3.5-9B-IQ4_XS.gguf` on an RTX 2050 (4 GB).

---

## Setup

### 1. Server (once)

```bash
git clone https://github.com/<your-account>/mcp-threatintel.git ~/mcp-threatintel
cd ~/mcp-threatintel
sudo ANALYST_IP=<analyst PC IP> bash scripts/ubuntu/setup-ubuntu.sh
```

The script installs the agent as a systemd service, creates a self-signed TLS certificate for the
server's IP, loads the nftables rules (agent ports reachable only from `ANALYST_IP`) and writes the
**console bundle** to `/etc/threatintel/console/`.

The agent starts in **dry-run** mode. To execute responses for real:

```bash
sudo sed -i 's/^RESPONDER_DRY_RUN=true/RESPONDER_DRY_RUN=false/' /etc/threatintel/responder.env
sudo systemctl restart threatintel-responder
```

### 2. Analyst PC (once)

```powershell
git clone https://github.com/<your-account>/mcp-threatintel.git
cd mcp-threatintel
python -m venv .venv
.venv\Scripts\pip install -e .
copy .env.example .env          # add ABUSECH_API_KEY (and OTX_API_KEY)
mkdir console
scp -i <ssh key> <user>@<server IP>:/etc/threatintel/console/* console\
```

`console\` and `.env` are git-ignored: they hold the tokens, the pinned certificate and the API keys.

> **If the server's or the PC's IP changes,** re-run `setup-ubuntu.sh` with the new `ANALYST_IP`.
> Delete `/etc/threatintel/agent.crt` and `agent.key` first, so the certificate is issued for the
> new server IP. Then copy the console bundle again. A static IP on the VM avoids this.

### 3. Start (each session)

```powershell
# window 1: the model (adjust -ngl to your GPU memory)
.\llama-server.exe -m .\Qwen3.5-9B-IQ4_XS.gguf --jinja -c 8192 -ngl 18 --no-mmproj -fa on -ctk q8_0 -ctv q8_0 -ub 256 -b 512 --reasoning-budget 0

# window 2: the console
powershell -ExecutionPolicy Bypass -File scripts\windows\start-console.ps1
```

`start-console.ps1` opens four windows (MCP server, feed poller, dashboard, AI responder) and the
dashboard at `http://127.0.0.1:3720`. To chat with the model, open the WebUI at
`http://localhost:8080`, add the MCP server `http://127.0.0.1:3707/mcp`, and paste
`docs/qwen-system-prompt.md` as the system message.

> **Context size:** the AI responder fits its prompts into 8192 tokens. Full investigations typed in
> the WebUI chat send all 28 tool definitions and the whole conversation, so they need a larger `-c`.

---

## Demo scenarios (on the server)

| Scenario | Command | Expected |
|---|---|---|
| Malicious domain | `getent hosts c2.threatintel-lab.test` | alert + `sinkhole_domain` |
| C2 connection | `python3 ~/mcp-threatintel/lab/fake_c2_beacon.py` | CRITICAL + `kill_process` + `block_ip` |
| Malicious file | `cp ~/threatintel-lab/invoice_2026.pdf.exe.txt /tmp/update.bin` | alert + `quarantine_file` |
| Backdoor port | `python3 -m http.server 8770 &` | HIGH "new listening port" → AI decides |
| New privileged account | `sudo useradd -m labuser2 && sudo usermod -aG sudo labuser2` | CRITICAL → `lock_user` |
| Persistence | `echo '* * * * * root true' \| sudo tee /etc/cron.d/lab-test` | HIGH → `quarantine_file` |
| Reverse-shell technique | `sh -c 'sleep 300; echo /dev/tcp/x' &` | HIGH → `kill_process` |
| SSH brute force | 6 wrong passwords from another host | alert + `block_ip` (the analyst PC is allowlisted) |

Lab files are created with `python3 lab/create_test_files.py ~/threatintel-lab`. Proof on the
server:

```bash
sudo nft list set inet threatintel blocklist
grep threatintel /etc/hosts
```

---

## Project layout

```
src/mcp_threatintel/
  server.py          MCP server (28 tools)
  poller.py          feed sync + intel push to the agent
  slim.py            compact, lossless tool-result JSON
  clients/           abuse.ch, OTX, CISA, HIBP clients
  responder/         host agent: detection, behavior, rules, actions, backends (nftables, hosts, quarantine...)
  watch/             AI responder (llama-server tool loop) and notifications
  console/           dashboard
scripts/ubuntu/      server setup
scripts/windows/     PC setup and start-console.ps1
deploy/              systemd unit and nftables ruleset
lab/                 lab IOCs, test files, fake C2 beacon
docs/                run guides and the Qwen system prompt
tests/               pytest suite
```

## Tests

```powershell
.venv\Scripts\pip install -e ".[dev]"
.venv\Scripts\python -m pytest
```

## Useful commands

```bash
# server
systemctl status threatintel-responder
sudo journalctl -u threatintel-responder -f
threatintel-approve list | approve <id> | rollback <id> | mode
```

```powershell
# PC (in a window started by start-console.ps1)
.venv\Scripts\threatintel-approve mode
.venv\Scripts\mcp-threatintel-poller --push-only   # re-send the intel to the agent
```

More detail: [docs/RUN-SPLIT.md](docs/RUN-SPLIT.md), [docs/RUN-UBUNTU.md](docs/RUN-UBUNTU.md),
[docs/RUN-WINDOWS.md](docs/RUN-WINDOWS.md).

---

## Security notice

This project runs a privileged agent that blocks IPs, kills processes and locks accounts. Use it in a
lab or on servers you own. Keep the agent in dry-run mode until you have checked the allowlist.

## Credits and license

MIT License. Based on [mcp-threatintel](https://github.com/pete-builds/mcp-threatintel) by
Pete Stergion. The v2 detection, response, AI responder and dashboard were built on top of it.
