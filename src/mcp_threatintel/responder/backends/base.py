"""ResponseBackend interface and the command runner shared by all backends.

Every external command is an argv list run without a shell. In dry-run mode
the runner records the argv instead of executing it, and backends skip their
file/process side effects, so a dry-run action leaves the host untouched.
"""

from __future__ import annotations

import logging
import subprocess
from abc import ABC, abstractmethod

logger = logging.getLogger("threatintel.responder.backends")


class BackendError(RuntimeError):
    pass


class CommandRunner:
    def __init__(self, dry_run: bool):
        self.dry_run = dry_run

    def run(self, argv: list[str], log: list[str], *, check: bool = True, timeout: int = 60) -> str:
        """Run argv (never through a shell) and append it to ``log``."""
        if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
            raise BackendError("commands must be argv lists of strings")
        log.append(" ".join(argv))
        if self.dry_run:
            logger.info("[dry-run] %s", " ".join(argv))
            return ""
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, shell=False)
        out = (proc.stdout or b"").decode(errors="replace") + (proc.stderr or b"").decode(errors="replace")
        if check and proc.returncode != 0:
            raise BackendError(f"{argv[0]} exited {proc.returncode}: {out.strip()[:300]}")
        return out


class ResponseBackend(ABC):
    """apply() performs an approved action; rollback() undoes it from its saved state."""

    def __init__(self, runner: CommandRunner):
        self.runner = runner

    @property
    def dry_run(self) -> bool:
        return self.runner.dry_run

    @abstractmethod
    def apply(self, action: dict) -> dict:
        """Return a JSON-serialisable state; it is stored in the action result."""

    @abstractmethod
    def rollback(self, action: dict, state: dict) -> dict:
        """Undo ``action`` using the ``state`` apply() returned."""
