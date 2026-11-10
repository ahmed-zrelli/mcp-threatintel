"""Well-known services that must never raise an alert from a *feed* match.

Community feeds (OTX especially) sometimes list shared infrastructure
(public DNS, cloud CDNs, code hosting) because malware used it once.
Blocking or sinkholing those would break the server, so feed matches on
them are ignored. Lab IOCs (local_iocs) are never filtered, and the
response allowlist is still checked separately before any action.
"""

from __future__ import annotations

import ipaddress

BENIGN_DOMAIN_SUFFIXES = {
    # OS, packages, containers
    "ubuntu.com", "canonical.com", "launchpad.net", "snapcraft.io", "debian.org",
    "docker.com", "docker.io", "pypi.org", "pythonhosted.org", "python.org",
    # big platforms / CDNs
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "youtube.com",
    "microsoft.com", "windows.com", "windowsupdate.com", "live.com", "office.com", "azure.com",
    "apple.com", "icloud.com", "amazon.com", "amazonaws.com", "cloudfront.net",
    "cloudflare.com", "cloudflare-dns.com", "akamai.net", "akamaiedge.net", "fastly.net",
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    # the project's own feeds and services
    "abuse.ch", "alienvault.com", "cisa.gov", "haveibeenpwned.com", "huggingface.co",
}

BENIGN_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
}


def is_benign_domain(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return any(d == s or d.endswith("." + s) for s in BENIGN_DOMAIN_SUFFIXES)


def is_benign_ip(ip: str) -> bool:
    if ip in BENIGN_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified
