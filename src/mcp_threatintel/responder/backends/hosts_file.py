"""hosts-file sinkhole backend (Windows and Linux), for sinkhole_domain.

Entries live in a marked block and every line is tagged with its action id:

    # BEGIN threatintel (managed by mcp-threatintel, do not edit)
    0.0.0.0 evil.example # threatintel:12
    :: evil.example # threatintel:12
    # END threatintel

Writes are atomic (temp file + os.replace) and the original file is backed up
once, before the first change.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

from .base import BackendError, CommandRunner, ResponseBackend

BEGIN = "# BEGIN threatintel (managed by mcp-threatintel, do not edit)"
END = "# END threatintel"


class HostsFileBackend(ResponseBackend):
    def __init__(self, runner: CommandRunner, hosts_path: Path, backup_dir: Path):
        super().__init__(runner)
        self.hosts_path = Path(hosts_path)
        self.backup_dir = Path(backup_dir)

    def apply(self, action: dict) -> dict:
        domain = action["params"]["domain"]
        tag = f"# threatintel:{action['id']}"
        lines = [f"0.0.0.0 {domain} {tag}", f":: {domain} {tag}"]
        commands: list[str] = [f"append to {self.hosts_path}: {line}" for line in lines]
        if not self.dry_run:
            self._backup_once()
            text = self._read()
            head, block, tail = _split(text)
            block += lines
            self._write(head, block, tail)
        self._flush(commands)
        return {"domain": domain, "tag": tag, "lines": lines, "commands": commands}

    def rollback(self, action: dict, state: dict) -> dict:
        tag = state.get("tag") or f"# threatintel:{action['id']}"
        commands = [f"remove lines tagged '{tag}' from {self.hosts_path}"]
        removed = 0
        if not self.dry_run:
            head, block, tail = _split(self._read())
            kept = [ln for ln in block if not ln.endswith(tag)]
            removed = len(block) - len(kept)
            self._write(head, kept, tail)
        self._flush(commands)
        return {"removed_lines": removed, "commands": commands}

    # --- helpers ---

    def _read(self) -> str:
        try:
            return self.hosts_path.read_text(encoding="utf-8", errors="surrogateescape")
        except FileNotFoundError:
            return ""

    def _write(self, head: list[str], block: list[str], tail: list[str]) -> None:
        out = list(head)
        if block:
            out += [BEGIN, *block, END]
        out += tail
        text = "\n".join(out).rstrip("\n") + "\n"
        fd, tmp = tempfile.mkstemp(dir=self.hosts_path.parent, prefix=".hosts.threatintel.")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
                f.write(text.replace("\n", "\r\n") if sys.platform == "win32" else text)
            if self.hosts_path.exists():
                shutil.copymode(self.hosts_path, tmp)
            os.replace(tmp, self.hosts_path)
        except Exception as e:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise BackendError(f"could not write {self.hosts_path}: {e}") from e

    def _backup_once(self) -> None:
        backup = self.backup_dir / "hosts.original"
        if not backup.exists() and self.hosts_path.exists():
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.hosts_path, backup)

    def _flush(self, commands: list[str]) -> None:
        if sys.platform == "win32":
            self.runner.run(["ipconfig", "/flushdns"], commands, check=False)
        elif shutil.which("resolvectl"):
            self.runner.run(["resolvectl", "flush-caches"], commands, check=False)


def _split(text: str) -> tuple[list[str], list[str], list[str]]:
    """Split the file into (before, managed block body, after)."""
    lines = text.replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if BEGIN in lines and END in lines[lines.index(BEGIN):]:
        b = lines.index(BEGIN)
        e = lines.index(END, b)
        return lines[:b], lines[b + 1:e], lines[e + 1:]
    return lines, [], []
