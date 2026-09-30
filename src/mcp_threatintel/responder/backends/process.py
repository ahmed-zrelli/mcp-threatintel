"""Process backend (psutil, Windows and Linux), for kill_process. Irreversible."""

from __future__ import annotations

import psutil

from .base import BackendError, ResponseBackend


class ProcessBackend(ResponseBackend):
    def apply(self, action: dict) -> dict:
        p = action["params"]
        pid, expected_ct = int(p["pid"]), float(p["create_time"])
        commands = [f"terminate PID {pid} ({p.get('name')}), kill after 5s if still alive"]
        try:
            proc = psutil.Process(pid)
            if abs(proc.create_time() - expected_ct) > 0.01:
                raise BackendError(f"PID {pid} now belongs to another process; not killing it")
        except psutil.NoSuchProcess:
            raise BackendError(f"PID {pid} has already exited") from None
        if self.dry_run:
            return {"pid": pid, "name": p.get("name"), "method": "none (dry-run)", "commands": commands}
        try:
            proc.terminate()
            _, alive = psutil.wait_procs([proc], timeout=5)
            method = "terminate"
            if alive:
                proc.kill()
                psutil.wait_procs([proc], timeout=5)
                method = "kill"
        except psutil.NoSuchProcess:
            method = "exited"
        except psutil.AccessDenied as e:
            raise BackendError(f"access denied killing PID {pid}: {e}") from e
        return {"pid": pid, "name": p.get("name"), "method": method, "commands": commands}

    def rollback(self, action: dict, state: dict) -> dict:
        raise BackendError("kill_process is irreversible")
