"""URL utilities: scope checking, normalization, host extraction."""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse

# RFC1918 private + loopback + link-local ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def extract_host(url: str) -> str:
    return urlparse(url).netloc.split(":")[0]


def is_private_ip(host: str) -> bool:
    """Return True if host resolves to a private/loopback IP."""
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        pass
    try:
        addr = socket.gethostbyname(host)
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _PRIVATE_NETWORKS)
    except (socket.gaierror, ValueError):
        return False


def host_matches_pattern(host: str, pattern: str) -> bool:
    """
    Check if host matches a scope pattern.
    Supports wildcards: *.example.com matches sub.example.com
    Supports exact: example.com matches example.com
    """
    if pattern.startswith("*."):
        suffix = pattern[1:]  # .example.com
        return host == suffix[1:] or host.endswith(suffix)
    return host == pattern


def is_in_scope(url: str, include_patterns: list[str], exclude_patterns: list[str]) -> bool:
    """Return True if URL is within scan scope."""
    host = extract_host(url)

    # Check exclude first
    for pattern in exclude_patterns:
        if host_matches_pattern(host, pattern):
            return False

    # Must match at least one include pattern
    if not include_patterns:
        return True
    return any(host_matches_pattern(host, p) for p in include_patterns)


def normalize_url(url: str, base: str) -> str:
    """Resolve a potentially relative URL against a base URL."""
    if url.startswith(("http://", "https://")):
        return url
    return urljoin(base, url)
