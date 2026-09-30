"""Strict parameter validation and the allowlist.

Everything an action targets passes through here twice: when the action is
created, and again when the analyst approves it (and once more right before
the backend runs). Validators raise ValidationError with a message meant for
the audit log and the analyst.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

import psutil

logger = logging.getLogger("threatintel.responder.validators")

IS_WINDOWS = sys.platform == "win32"

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z][a-z0-9-]{0,62}$")

#: Processes that must never be killed, whatever the model asks.
PROTECTED_PROCESSES = {
    # Windows core
    "system", "system idle process", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "fontdrvhost.exe",
    "dwm.exe", "explorer.exe", "msmpeng.exe", "memory compression", "securityhealthservice.exe",
    # Linux core
    "systemd", "init", "kthreadd", "sshd", "dockerd", "containerd", "journald", "systemd-journald",
    # This project
    "llama-server", "llama-server.exe",
    "mcp-threatintel.exe", "mcp-threatintel-poller.exe", "threatintel-responder.exe",
    "threatintel-approve.exe",
}

#: The project's own components usually run as python(.exe); recognise them by
#: their command line so a model cannot kill the server, poller or agent.
PROTECTED_ENTRYPOINTS = {
    "mcp-threatintel", "mcp-threatintel-poller", "threatintel-responder", "threatintel-approve",
}


def _is_project_process(cmdline: list[str]) -> bool:
    for arg in cmdline[1:4]:
        base = os.path.basename(arg).lower()
        for suffix in (".exe", "-script.py"):
            if base.endswith(suffix):
                base = base[: -len(suffix)]
        if base in PROTECTED_ENTRYPOINTS or arg.startswith("mcp_threatintel"):
            return True
    return False


class ValidationError(ValueError):
    pass


# --- individual validators -------------------------------------------------


def validate_ip(value: str, *, allow_private: bool = False) -> str:
    try:
        ip = ipaddress.IPv4Address(str(value).strip())
    except ValueError:
        raise ValidationError(f"not a valid IPv4 address: {value!r}") from None
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        raise ValidationError(f"refusing to block special-purpose address {ip}")
    if ip.is_private and not allow_private:
        raise ValidationError(
            f"{ip} is a private (LAN) address; it can only be blocked if it is listed in local_iocs"
        )
    return str(ip)


def validate_domain(value: str) -> str:
    domain = str(value).strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(domain):
        raise ValidationError(f"not a valid domain name: {value!r}")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValidationError("an IP address is not a domain; use block_ip")


def validate_path(value: str, scan_paths: list[Path]) -> Path:
    if not scan_paths:
        raise ValidationError("SCAN_PATHS is empty: no directory is authorised")
    try:
        path = Path(value).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValidationError(f"path does not exist: {value!r}") from None
    roots = [p.expanduser().resolve() for p in scan_paths]
    if not any(path == r or path.is_relative_to(r) for r in roots):
        raise ValidationError(f"{path} is outside SCAN_PATHS ({', '.join(map(str, roots))})")
    return path


def validate_file(value: str, scan_paths: list[Path]) -> Path:
    path = validate_path(value, scan_paths)
    if not path.is_file():
        raise ValidationError(f"not a regular file: {path}")
    return path


def validate_pid(value, *, protected: set[str] | None = None) -> dict:
    try:
        pid = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"not a PID: {value!r}") from None
    if pid <= 4:
        raise ValidationError(f"refusing to touch system PID {pid}")
    own = {os.getpid(), os.getppid()}
    if pid in own:
        raise ValidationError("refusing to kill the host agent itself")
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        create_time = proc.create_time()
        try:
            cmdline = proc.cmdline()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            cmdline = []
    except psutil.NoSuchProcess:
        raise ValidationError(f"no process with PID {pid}") from None
    except psutil.AccessDenied:
        raise ValidationError(f"access denied to PID {pid} (is the agent elevated?)") from None
    if name.lower() in (protected or PROTECTED_PROCESSES):
        raise ValidationError(f"{name} (PID {pid}) is a protected process")
    if _is_project_process(cmdline):
        raise ValidationError(f"PID {pid} is a mcp-threatintel component; refusing to kill it")
    return {"pid": pid, "name": name, "create_time": create_time}


# --- allowlist ---------------------------------------------------------------


class Allowlist:
    """Targets that must never be acted on: IPs/CIDRs, domain suffixes, process names."""

    def __init__(self, entries: list[dict] | None = None):
        self.entries: list[dict] = []
        self._nets: list[tuple[ipaddress.IPv4Network, str]] = []
        self._domains: list[tuple[str, str]] = []
        self._procs: dict[str, str] = {}
        for e in entries or []:
            self.add(e["value"], e["type"], e.get("comment") or "")

    def add(self, value: str, type_: str, comment: str = "") -> None:
        value = value.strip()
        if not value:
            return
        try:
            if type_ in ("ip", "cidr"):
                self._nets.append((ipaddress.IPv4Network(value, strict=False), comment))
            elif type_ == "domain":
                self._domains.append((value.lower().lstrip("*.").rstrip("."), comment))
            elif type_ == "process":
                self._procs[value.lower()] = comment
            else:
                return
        except ValueError:
            logger.warning("ignoring invalid allowlist entry %s %r", type_, value)
            return
        self.entries.append({"value": value, "type": type_, "comment": comment})

    def check_ip(self, ip: str) -> str | None:
        """Return the reason the IP is protected, or None."""
        addr = ipaddress.IPv4Address(ip)
        for net, comment in self._nets:
            if addr in net:
                return f"{ip} is allowlisted ({net}: {comment or 'no comment'})"
        return None

    def check_domain(self, domain: str) -> str | None:
        for suffix, comment in self._domains:
            if domain == suffix or domain.endswith("." + suffix):
                return f"{domain} is allowlisted ({suffix}: {comment or 'no comment'})"
        return None

    def check_process(self, name: str) -> str | None:
        comment = self._procs.get(name.lower())
        if comment is not None:
            return f"process {name} is allowlisted ({comment or 'no comment'})"
        return None

    @property
    def protected_processes(self) -> set[str]:
        return PROTECTED_PROCESSES | set(self._procs)


def load_allowlist_file(path: Path | None) -> list[tuple[str, str, str]]:
    """Read the lab allowlist CSV (value,type,comment; '#' lines ignored)."""
    if not path or not path.exists():
        return []
    with open(path, newline="", encoding="utf-8") as f:
        lines = [line for line in f if line.strip() and not line.lstrip().startswith("#")]
    return [
        (r["value"].strip(), r["type"].strip(), (r.get("comment") or "file").strip())
        for r in csv.DictReader(lines) if r.get("value") and r.get("type")
    ]


def discover_allowlist() -> list[tuple[str, str, str]]:
    """Entries that protect the machine's own connectivity, found at startup."""
    entries: list[tuple[str, str, str]] = [
        ("127.0.0.0/8", "cidr", "loopback"),
        ("0.0.0.0/32", "ip", "unspecified"),
        ("microsoft.com", "domain", "OS updates / Defender"),
        ("windowsupdate.com", "domain", "OS updates"),
        ("windows.com", "domain", "OS services"),
        ("ubuntu.com", "domain", "OS updates"),
    ]
    for iface, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family.name == "AF_INET" and a.address:
                entries.append((a.address, "ip", f"own address ({iface})"))
    gateways, dns = _gateways_and_dns()
    entries += [(g, "ip", "default gateway") for g in gateways]
    entries += [(d, "ip", "DNS server") for d in dns]
    return entries


def _gateways_and_dns() -> tuple[list[str], list[str]]:
    gateways: list[str] = []
    dns: list[str] = []
    try:
        if IS_WINDOWS:
            # Fixed script, no interpolation: output is JSON regardless of OS language.
            script = (
                "$g=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
                "Select-Object -ExpandProperty NextHop);"
                "$d=@(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
                "Select-Object -ExpandProperty ServerAddresses);"
                "@{g=$g;d=$d} | ConvertTo-Json -Compress"
            )
            out = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, timeout=20,
            ).stdout
            data = json.loads(out or "{}")
            gateways = [g for g in _as_list(data.get("g")) if g and g != "0.0.0.0"]
            dns = _as_list(data.get("d"))
        else:
            out = subprocess.run(["ip", "-4", "route", "show", "default"],
                                 capture_output=True, text=True, timeout=10).stdout
            gateways = re.findall(r"via (\d+\.\d+\.\d+\.\d+)", out)
            for resolv in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
                if os.path.exists(resolv):
                    with open(resolv) as f:
                        dns += re.findall(r"^nameserver\s+(\d+\.\d+\.\d+\.\d+)", f.read(), re.M)
    except Exception as e:  # discovery must never stop the agent
        logger.warning("gateway/DNS discovery failed: %s", e)
    valid = []
    for ip in gateways + dns:
        try:
            ipaddress.IPv4Address(ip)
            valid.append(ip)
        except ValueError:
            pass
    return [g for g in gateways if g in valid], sorted({d for d in dns if d in valid})


def _as_list(v) -> list[str]:
    if v is None:
        return []
    return [str(x) for x in v] if isinstance(v, list) else [str(v)]
