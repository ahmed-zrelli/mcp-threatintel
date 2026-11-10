"""Linux nftables backend, for block_ip and block_feed_c2.

Everything lives in a dedicated table, ``inet threatintel`` (deploy/threatintel.nft),
so the host's own rules (Docker, ufw, ...) are never touched:

    set blocklist { type ipv4_addr; flags timeout; }
    input/forward/output chains drop traffic from/to @blocklist

An approved block adds the IPs to the set with a timeout slightly longer than
the action's TTL: the agent's own expiry removes them first and records it,
and the kernel timeout is a safety net if the agent is down. Rollback removes
exactly the IPs the action added, except those still covered by another
executed action.
"""

from __future__ import annotations

from pathlib import Path

from .base import BackendError, CommandRunner, ResponseBackend

TABLE = ("inet", "threatintel")
SET = "blocklist"
CHUNK = 500
TIMEOUT_MARGIN_S = 120


class NftablesBackend(ResponseBackend):
    def __init__(self, runner: CommandRunner, ruleset_file: Path | None = None, seconds_per_unit: int = 3600):
        super().__init__(runner)
        self.ruleset_file = Path(ruleset_file) if ruleset_file else None
        self.seconds_per_unit = seconds_per_unit

    # --- table management ---

    def ensure_table(self, commands: list[str] | None = None) -> bool:
        """Load the ruleset if the table is missing (e.g. after a reboot). Returns True if it exists."""
        log = commands if commands is not None else []
        if self.dry_run:
            return True
        if self._table_exists():
            return True
        if not self.ruleset_file or not self.ruleset_file.exists():
            raise BackendError("nftables table inet threatintel is missing and NFT_RULESET_FILE is not set")
        self.runner.run(["nft", "-f", str(self.ruleset_file)], log)
        return self._table_exists()

    def _table_exists(self) -> bool:
        try:
            self.runner.run(["nft", "list", "table", *TABLE], [], timeout=15)
            return True
        except BackendError:
            return False

    # --- ResponseBackend ---

    def _ips(self, action: dict) -> list[str]:
        p = action["params"]
        return list(p["ips"]) if "ips" in p else [p["ip"]]

    def apply(self, action: dict) -> dict:
        ips = self._ips(action)
        commands: list[str] = []
        self.ensure_table(commands)
        ttl = float(action["params"].get("ttl", 24))
        timeout = int(ttl * self.seconds_per_unit) + TIMEOUT_MARGIN_S
        for i in range(0, len(ips), CHUNK):
            chunk = ips[i:i + CHUNK]
            elements = ", ".join(f'{ip} timeout {timeout}s comment "threatintel-{action["id"]}"' for ip in chunk)
            self.runner.run(["nft", "add", "element", *TABLE, SET, "{ " + elements + " }"], commands)
        return {"table": " ".join(TABLE), "set": SET, "ips": ips, "ip_count": len(ips),
                "kernel_timeout_s": timeout, "commands": commands}

    def rollback(self, action: dict, state: dict) -> dict:
        ips = state.get("ips") or self._ips(action)
        keep = set(state.get("keep_ips") or [])
        to_remove = [ip for ip in ips if ip not in keep]
        commands: list[str] = []
        for i in range(0, len(to_remove), CHUNK):
            chunk = to_remove[i:i + CHUNK]
            try:
                # "destroy" (nftables >= 1.0.8) ignores elements that already timed out.
                self.runner.run(["nft", "destroy", "element", *TABLE, SET, "{ " + ", ".join(chunk) + " }"], commands)
            except BackendError:
                for ip in chunk:  # older nft: one by one, tolerating already-gone elements
                    self.runner.run(["nft", "delete", "element", *TABLE, SET, "{ " + ip + " }"], commands, check=False)
        return {"removed_ips": to_remove, "kept_ips": sorted(keep & set(ips)), "commands": commands}

    def reapply(self, action: dict, seconds_left: int) -> None:
        """Re-add a still-valid block after a reboot (the kernel set starts empty)."""
        ips = self._ips(action)
        timeout = max(int(seconds_left), 1) + TIMEOUT_MARGIN_S
        for i in range(0, len(ips), CHUNK):
            elements = ", ".join(f'{ip} timeout {timeout}s comment "threatintel-{action["id"]}"' for ip in ips[i:i + CHUNK])
            self.runner.run(["nft", "add", "element", *TABLE, SET, "{ " + elements + " }"], [], check=False)
