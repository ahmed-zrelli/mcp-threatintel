"""Windows Defender Firewall backend (netsh), for block_ip and block_feed_c2.

Each action gets its own named rules (threatintel-<id>-in / -out), so a
rollback or expiry deletes exactly what the action added and nothing else.
"""

from __future__ import annotations

from .base import ResponseBackend

CHUNK = 1000  # remoteip list size per rule


class WindowsFirewallBackend(ResponseBackend):
    def _ips(self, action: dict) -> list[str]:
        p = action["params"]
        return list(p["ips"]) if "ips" in p else [p["ip"]]

    def apply(self, action: dict) -> dict:
        ips = self._ips(action)
        commands: list[str] = []
        rules: list[str] = []
        chunks = [ips[i:i + CHUNK] for i in range(0, len(ips), CHUNK)]
        try:
            for n, chunk in enumerate(chunks):
                suffix = f"-{n}" if len(chunks) > 1 else ""
                for direction in ("in", "out"):
                    name = f"threatintel-{action['id']}-{direction}{suffix}"
                    self.runner.run([
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={name}", f"dir={direction}", "action=block", "enable=yes",
                        "profile=any", f"remoteip={','.join(chunk)}",
                        f"description=mcp-threatintel action {action['id']}",
                    ], commands)
                    rules.append(name)
        except Exception:
            self._delete(rules, commands)  # never leave half an action behind
            raise
        return {"rules": rules, "ip_count": len(ips), "commands": commands}

    def rollback(self, action: dict, state: dict) -> dict:
        commands: list[str] = []
        self._delete(state.get("rules", []), commands)
        return {"removed_rules": state.get("rules", []), "commands": commands}

    def _delete(self, rules: list[str], commands: list[str]) -> None:
        for name in rules:
            self.runner.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                commands, check=False,
            )
