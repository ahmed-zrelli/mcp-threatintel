"""Responder configuration, read from the environment (and .env)."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    _DATA_DIR = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "threatintel"
    _HOSTS = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    _AGENT_ADDR = "tcp://127.0.0.1:3710"
    _ADMIN_ADDR = "tcp://127.0.0.1:3711"
else:
    _DATA_DIR = Path("/var/lib/threatintel")
    _HOSTS = Path("/etc/hosts")
    _AGENT_ADDR = "unix:///run/threatintel/agent.sock"
    _ADMIN_ADDR = "unix:///run/threatintel/admin.sock"


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _paths(name: str) -> list[Path]:
    raw = os.getenv(name, "")
    # os.pathsep is ";" on Windows (paths contain ":") and ":" on Linux.
    return [Path(p.strip()).expanduser() for p in raw.split(os.pathsep) if p.strip()]


@dataclass
class ResponderConfig:
    agent_addr: str = _AGENT_ADDR
    admin_addr: str = _ADMIN_ADDR
    agent_token: str = ""
    data_dir: Path = _DATA_DIR
    admin_token_file: Path = _DATA_DIR / "admin.token"
    responder_db: Path = _DATA_DIR / "responder.db"
    ioc_db: Path = Path("/data/threatintel.db")
    quarantine_dir: Path = _DATA_DIR / "quarantine"
    hosts_path: Path = _HOSTS
    allowlist_file: Path | None = None
    scan_paths: list[Path] = field(default_factory=list)
    dry_run: bool = True
    block_ttl: float = 24.0
    ttl_unit: str = "hours"  # "minutes" is handy for testing expiry
    auth_fail_threshold: int = 5
    max_results: int = 10

    @property
    def ttl_seconds_per_unit(self) -> int:
        return 60 if self.ttl_unit == "minutes" else 3600

    @classmethod
    def from_env(cls) -> "ResponderConfig":
        load_dotenv()
        data_dir = Path(os.getenv("RESPONDER_DATA_DIR", str(_DATA_DIR)))
        allowlist = os.getenv("ALLOWLIST_FILE", "lab/allowlist.csv")
        return cls(
            agent_addr=os.getenv("AGENT_ADDR", _AGENT_ADDR),
            admin_addr=os.getenv("ADMIN_ADDR", _ADMIN_ADDR),
            agent_token=os.getenv("AGENT_TOKEN", "").strip(),
            data_dir=data_dir,
            admin_token_file=Path(os.getenv("ADMIN_TOKEN_FILE", str(data_dir / "admin.token"))),
            responder_db=Path(os.getenv("RESPONDER_DB", str(data_dir / "responder.db"))),
            ioc_db=Path(os.getenv("DB_PATH", "/data/threatintel.db")),
            quarantine_dir=Path(os.getenv("QUARANTINE_DIR", str(data_dir / "quarantine"))),
            hosts_path=Path(os.getenv("HOSTS_PATH", str(_HOSTS))),
            allowlist_file=Path(allowlist) if allowlist else None,
            scan_paths=_paths("SCAN_PATHS"),
            dry_run=_bool("RESPONDER_DRY_RUN", True),
            block_ttl=float(os.getenv("BLOCK_DEFAULT_TTL", os.getenv("BLOCK_DEFAULT_TTL_HOURS", "24"))),
            ttl_unit=os.getenv("BLOCK_TTL_UNIT", "hours").strip().lower(),
            auth_fail_threshold=int(os.getenv("AUTH_FAIL_THRESHOLD", "5")),
            max_results=int(os.getenv("SCAN_MAX_RESULTS", "10")),
        )
