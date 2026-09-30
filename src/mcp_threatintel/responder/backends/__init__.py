"""Backend registry: which ResponseBackend performs which action type."""

from __future__ import annotations

import sys

from ..config import ResponderConfig
from .base import BackendError, CommandRunner, ResponseBackend
from .hosts_file import HostsFileBackend
from .nftables import NftablesBackend
from .process import ProcessBackend
from .quarantine import QuarantineBackend
from .windows_firewall import WindowsFirewallBackend

__all__ = ["BackendError", "CommandRunner", "ResponseBackend", "build_backends"]


def build_backends(config: ResponderConfig, runner: CommandRunner | None = None) -> dict[str, ResponseBackend]:
    runner = runner or CommandRunner(config.dry_run)
    firewall: ResponseBackend = (
        WindowsFirewallBackend(runner) if sys.platform == "win32" else NftablesBackend(runner)
    )
    return {
        "block_ip": firewall,
        "block_feed_c2": firewall,
        "sinkhole_domain": HostsFileBackend(runner, config.hosts_path, config.data_dir / "backup"),
        "quarantine_file": QuarantineBackend(runner, config.quarantine_dir),
        "kill_process": ProcessBackend(runner),
    }
