# mcp-threatintel v2 on the Ubuntu server (phase 2)

The Ubuntu server is the protected infrastructure. The MCP server, the poller
and the privileged host agent all run on it, and every action (firewall block,
DNS sinkhole, quarantine, process kill) happens **on the server**. The analyst
PC only runs Qwen (llama-server + WebUI) and connects to the MCP server over
the network.

```
Analyst PC (Windows)                         Ubuntu server (protected)
  llama-server + WebUI  ──HTTP :3707/mcp──▶  [docker] mcp-threatintel ──agent.sock──▶ threatintel-responder (systemd, root)
  ssh  ──────────────────────────────────▶   threatintel-approve ──admin.sock──▶        │  nftables · /etc/hosts
                                             [docker] threatintel-poller ──▶ threatintel.db   quarantine · processes
```

## Install (once, on the server)

Copy the project to the server (with your `.env` holding `ABUSECH_API_KEY`), then:

```bash
cd ~/mcp-threatintel
sudo ANALYST_IP=<your PC IP> bash scripts/ubuntu/setup-ubuntu.sh
```

It installs nftables, Docker Compose and a Python venv in `/opt/threatintel`,
creates the `threatintel` and `threatintel-admin` groups, loads the firewall
table `inet threatintel` (port 3707 open to `ANALYST_IP` only), installs the
agent as the systemd service `threatintel-responder` (dry-run first), builds
the image and starts both containers. Re-running it is safe.

| Path | Content | Access |
|---|---|---|
| `/etc/threatintel/responder.env` | agent settings, `AGENT_TOKEN` | root only |
| `/etc/threatintel/admin.token` | approval token | root + `threatintel-admin` |
| `/etc/threatintel/threatintel.nft` | firewall table | read-only |
| `/var/lib/threatintel/data/` | `threatintel.db` (cache) | containers (UID 1000), agent reads |
| `/var/lib/threatintel/responder/` | `responder.db`, quarantine, hosts backup | root only |
| `/run/threatintel/agent.sock` | MCP container → agent | `threatintel` group |
| `/run/threatintel-admin/admin.sock` | analyst CLI → agent | `threatintel-admin` group |

## Use

- WebUI on the PC: MCP server `http://<server IP>:3707/mcp`.
- Approve from the PC: `ssh <server>` then `threatintel-approve list` /
  `threatintel-approve approve <id>` (log in again once after install so the
  `threatintel-admin` group applies).
- Real mode: set `RESPONDER_DRY_RUN=false` in `/etc/threatintel/responder.env`,
  then `sudo systemctl restart threatintel-responder`.

## Check

```bash
sudo nft list table inet threatintel        # blocklist set and rules
sudo systemctl status threatintel-responder
sudo journalctl -u threatintel-responder -f
docker compose ps && docker compose logs -f
threatintel-approve audit
```

After a reboot the agent reloads the table and re-applies the blocks that are
still valid.
