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
    _ADMIN_TOKEN = None  # derived from data_dir (RESPONDER_DATA_DIR)
    _EXTRA_SCAN_PATHS = ""
else:
    # Linux layout (scripts/ubuntu/setup-ubuntu.sh). The two sockets live in
    # separate directories so the MCP container can be given the agent one
    # without ever seeing the admin one.
    _DATA_DIR = Path("/var/lib/threatintel/responder")
    _HOSTS = Path("/etc/hosts")
    _AGENT_ADDR = "unix:///run/threatintel/agent.sock"
    _ADMIN_ADDR = "unix:///run/threatintel-admin/admin.sock"
    _ADMIN_TOKEN = Path("/etc/threatintel/admin.token")
    _EXTRA_SCAN_PATHS = "/tmp:/var/tmp:/dev/shm"


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _paths(name: str, default: str = "") -> list[Path]:
    raw = os.getenv(name, default)
    # os.pathsep is ";" on Windows (paths contain ":") and ":" on Linux.
    return [Path(p.strip()).expanduser() for p in raw.split(os.pathsep) if p.strip()]


@dataclass
class ResponderConfig:
    agent_addr: str = _AGENT_ADDR
    admin_addr: str = _ADMIN_ADDR
    agent_token: str = ""
    data_dir: Path = _DATA_DIR
    admin_token_file: Path = _ADMIN_TOKEN or _DATA_DIR / "admin.token"
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
    # Linux: groups that may use each Unix socket (agent: MCP container; admin: analyst)
    agent_socket_group: str = "threatintel"
    admin_socket_group: str = "threatintel-admin"
    nft_ruleset_file: Path | None = None
    # Always-on detection inside the agent (AlertEngine)
    auto_detect: bool = True
    detect_interval: int = 30
    # Autonomous mode: the model may resolve alerts itself (off = human approval only)
    autonomy: bool = False
    autonomy_actions: tuple = ("block_ip", "sinkhole_domain", "quarantine_file")
    autonomy_max_per_hour: int = 20

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
            admin_token_file=Path(os.getenv("ADMIN_TOKEN_FILE", str(_ADMIN_TOKEN or data_dir / "admin.token"))),
            responder_db=Path(os.getenv("RESPONDER_DB", str(data_dir / "responder.db"))),
            ioc_db=Path(os.getenv("DB_PATH", "/data/threatintel.db")),
            quarantine_dir=Path(os.getenv("QUARANTINE_DIR", str(data_dir / "quarantine"))),
            hosts_path=Path(os.getenv("HOSTS_PATH", str(_HOSTS))),
            allowlist_file=Path(allowlist) if allowlist else None,
            # SCAN_PATHS (lab folder...) plus the usual malware drop locations.
            scan_paths=list(dict.fromkeys(_paths("SCAN_PATHS") + _paths("EXTRA_SCAN_PATHS", _EXTRA_SCAN_PATHS))),
            dry_run=_bool("RESPONDER_DRY_RUN", True),
            block_ttl=float(os.getenv("BLOCK_DEFAULT_TTL", os.getenv("BLOCK_DEFAULT_TTL_HOURS", "24"))),
            ttl_unit=os.getenv("BLOCK_TTL_UNIT", "hours").strip().lower(),
            auth_fail_threshold=int(os.getenv("AUTH_FAIL_THRESHOLD", "5")),
            max_results=int(os.getenv("SCAN_MAX_RESULTS", "10")),
            agent_socket_group=os.getenv("AGENT_SOCKET_GROUP", "threatintel"),
            admin_socket_group=os.getenv("ADMIN_SOCKET_GROUP", "threatintel-admin"),
            nft_ruleset_file=Path(os.environ["NFT_RULESET_FILE"]) if os.getenv("NFT_RULESET_FILE") else None,
            auto_detect=_bool("AUTO_DETECT", True),
            detect_interval=max(10, int(os.getenv("AUTO_DETECT_INTERVAL", "30"))),
            autonomy=os.getenv("AUTONOMY", "off").strip().lower() in {"1", "on", "true", "yes"},
            autonomy_actions=tuple(a.strip() for a in os.getenv(
                "AUTONOMY_ACTIONS", "block_ip,sinkhole_domain,quarantine_file").split(",") if a.strip()),
            autonomy_max_per_hour=int(os.getenv("AUTONOMY_MAX_PER_HOUR", "20")),
        )
