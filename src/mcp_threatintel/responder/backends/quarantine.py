"""File quarantine backend (Windows and Linux), for quarantine_file.

The file is moved to QUARANTINE_DIR/<sha256>_<action id> (no extension, so it
cannot be double-clicked) and locked down: on Windows the ACL is reduced to
Administrators and SYSTEM (by SID, so it works on any OS language); on Linux
the mode becomes 000. Rollback moves it back and restores its permissions.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import sys
from pathlib import Path

from .base import BackendError, CommandRunner, ResponseBackend

ADMINS_SID = "*S-1-5-32-544"
SYSTEM_SID = "*S-1-5-18"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


class QuarantineBackend(ResponseBackend):
    def __init__(self, runner: CommandRunner, quarantine_dir: Path):
        super().__init__(runner)
        self.quarantine_dir = Path(quarantine_dir)

    def apply(self, action: dict) -> dict:
        src = Path(action["params"]["path"])
        if not src.is_file():
            raise BackendError(f"{src} no longer exists")
        digest = sha256_file(src)
        st = src.stat()
        dest = self.quarantine_dir / f"{digest}_{action['id']}"
        commands = [f"move {src} -> {dest}"]
        state = {"original_path": str(src), "quarantine_path": str(dest), "sha256": digest,
                 "size": st.st_size, "mode": stat.S_IMODE(st.st_mode), "commands": commands}
        if sys.platform == "win32":
            lock = ["icacls", str(dest), "/inheritance:r", "/grant:r", f"{ADMINS_SID}:F", f"{SYSTEM_SID}:F"]
        else:
            lock = None
            commands.append(f"chmod 000 {dest}")
        if self.dry_run:
            if lock:
                self.runner.run(lock, commands)
            return state
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dest))
        try:
            if lock:
                self.runner.run(lock, commands)
            else:
                os.chmod(dest, 0)
        except Exception:
            shutil.move(str(dest), str(src))  # could not lock it: put it back, fail loudly
            raise
        return state

    def rollback(self, action: dict, state: dict) -> dict:
        dest = Path(state["quarantine_path"])
        original = Path(state["original_path"])
        commands = [f"move {dest} -> {original}"]
        if not self.dry_run:
            if original.exists():
                raise BackendError(f"{original} exists again; refusing to overwrite it")
            if not dest.exists():
                raise BackendError(f"{dest} is missing from quarantine")
            if sys.platform != "win32":
                os.chmod(dest, state.get("mode", 0o644))
            original.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(dest), str(original))
        if sys.platform == "win32":
            # Re-inherit the permissions of the folder it came back to.
            self.runner.run(["icacls", str(original), "/reset"], commands)
        else:
            commands.append(f"chmod {oct(state.get('mode', 0o644))} {original}")
        return {"restored_to": str(original), "commands": commands}
