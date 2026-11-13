"""Account backend, for lock_user. Reversible.

Linux: ``usermod -L -e 1 <user>`` locks the password AND expires the account,
so key-based SSH logins are refused too (the PAM account check fails). The
previous lock state and expiry date are saved; rollback restores them.
Windows: ``net user <name> /active:no`` / ``/active:yes``.

Sessions already open are not closed (that would be a kill_process).
"""

from __future__ import annotations

import sys
from datetime import date, timedelta

from .base import ResponseBackend

SHADOW = "/etc/shadow"


def shadow_entry(user: str, path: str = SHADOW) -> dict | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split(":")
                if parts[0] == user and len(parts) >= 8:
                    return {"locked": parts[1].startswith("!"), "expire": parts[7]}
    except OSError:
        return None
    return None


def _expire_arg(days: str) -> str:
    if not days:
        return ""
    try:
        return (date(1970, 1, 1) + timedelta(days=int(days))).isoformat()
    except ValueError:
        return ""


class UserBackend(ResponseBackend):
    def apply(self, action: dict) -> dict:
        user = action["params"]["user"]
        commands: list[str] = []
        if sys.platform == "win32":
            self.runner.run(["net", "user", user, "/active:no"], commands)
            return {"user": user, "commands": commands}
        before = None if self.dry_run else shadow_entry(user)
        self.runner.run(["usermod", "-L", "-e", "1", user], commands)
        return {"user": user, "previous": before, "commands": commands,
                "note": "new logins refused (password and SSH keys); open sessions are not closed"}

    def rollback(self, action: dict, state: dict) -> dict:
        user = state.get("user") or action["params"]["user"]
        commands: list[str] = []
        if sys.platform == "win32":
            self.runner.run(["net", "user", user, "/active:yes"], commands)
            return {"user": user, "commands": commands}
        prev = state.get("previous") or {"locked": False, "expire": ""}
        self.runner.run(["usermod", "-e", _expire_arg(prev.get("expire", "")), user], commands)
        if not prev.get("locked"):
            # Fails harmlessly ("passwordless account") for users that never had a password.
            self.runner.run(["usermod", "-U", user], commands, check=False)
        return {"user": user, "restored": prev, "commands": commands}
