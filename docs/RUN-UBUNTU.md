# mcp-threatintel v2 on the Ubuntu server

The Ubuntu server is the protected infrastructure. It runs **only the host agent**
(`threatintel-responder`, systemd, root): always-on detection and every response
action (nftables block, DNS sinkhole, quarantine, process kill, account lock) happen
**on the server**. The console (MCP server for Qwen, feed poller, dashboard) runs on
the analyst PC — see [RUN-SPLIT.md](RUN-SPLIT.md) for the full setup.

## Install (once, on the server)

```bash
cd ~/mcp-threatintel
sudo ANALYST_IP=<your PC IP> bash scripts/ubuntu/setup-ubuntu.sh
```

It installs nftables and a Python venv in `/opt/threatintel`, creates the
`threatintel` and `threatintel-admin` groups, loads the firewall table
`inet threatintel` (agent ports 3712/3713 open to `ANALYST_IP` only, SYN logging for
port-scan detection), creates the agent's TLS certificate and installs the agent
(dry-run first). Re-running it is safe. `WITH_CONTAINERS=1` also runs the old
all-on-the-server containers.

| Path | Content | Access |
|---|---|---|
| `/etc/threatintel/responder.env` | agent settings, `AGENT_TOKEN` | root only |
| `/etc/threatintel/admin.token` | admin-channel token | root + `threatintel-admin` |
| `/etc/threatintel/agent.key` / `agent.crt` | TLS key / certificate | key root only |
| `/etc/threatintel/console/` | bundle to copy to the PC | root + `threatintel-admin` |
| `/etc/threatintel/threatintel.nft` | firewall table | read-only |
| `/var/lib/threatintel/data/threatintel.db` | intel snapshot pushed by the console | agent |
| `/var/lib/threatintel/responder/` | `responder.db` (actions, alerts, audit, baselines), quarantine | root only |
| TLS `:3712` / `:3713` | agent / admin channel (from the PC) | analyst PC only |
| `/run/threatintel*/…sock` | the same channels, locally | groups above |

## Settings worth knowing (`responder.env`)

| Variable | Meaning |
|---|---|
| `RESPONDER_DRY_RUN` | `true` = commands only logged; `false` = applied |
| `ALLOWED_CLIENTS` | IPs allowed on the TLS channels (the analyst PC) |
| `PROTECTED_USERS` | accounts `lock_user` never touches (root, the analyst) |
| `AUTONOMY` | initial decision mode; the dashboard switch overrides it and is kept |

## Use on the server itself (optional)

`threatintel-approve list | approve <id> | reject <id> | rollback <id> | mode [human|ai] |
alerts | incidents | report` (log in again after install so the `threatintel-admin`
group applies).

## Check

```bash
sudo nft list table inet threatintel        # blocklist, port rules, ti-syn log rule
sudo systemctl status threatintel-responder
sudo journalctl -u threatintel-responder -f
sudo journalctl -k | grep ti-syn | tail     # inbound connection attempts seen for scan detection
threatintel-approve audit
```

After a reboot the agent reloads the table and re-applies the blocks that are still
valid. Behavior baselines (accounts, system files, listening ports) are stored in
`responder.db`, so changes made while the agent was stopped are reported at start.
