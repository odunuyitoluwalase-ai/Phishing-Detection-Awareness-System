"""
url_utils.py
Lightweight URL/domain parsing helpers (no external dependencies beyond stdlib).
"""

import re
import ipaddress
from urllib.parse import urlparse

# A short list of common two-part public suffixes so "co.uk" style domains
# are handled reasonably without pulling in a full public-suffix-list dependency.
_COMMON_TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "co.in", "co.nz",
    "com.au", "net.au", "org.au", "com.br", "com.cn", "com.mx",
}


def normalize_url(raw_url: str) -> str:
    """Ensure the URL has a scheme so urlparse behaves predictably."""
    raw_url = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
        raw_url = "http://" + raw_url
    return raw_url


def parse_url(raw_url: str):
    """Return a urllib ParseResult for a normalized URL."""
    return urlparse(normalize_url(raw_url))


def get_host(raw_url: str) -> str:
    parsed = parse_url(raw_url)
    return parsed.hostname or ""


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def split_domain(host: str):
    """
    Split a hostname into (subdomains, root_domain, suffix).
    Best-effort, stdlib-only approximation (not a full PSL implementation).
    """
    if not host or is_ip_address(host):
        return [], host, ""

    labels = host.lower().strip(".").split(".")
    if len(labels) < 2:
        return [], host, ""

    last_two = ".".join(labels[-2:])
    if last_two in _COMMON_TWO_PART_SUFFIXES and len(labels) >= 3:
        suffix = ".".join(labels[-3:])
        root = labels[-3]
        subs = labels[:-3]
    else:
        suffix = labels[-1]
        root = labels[-2]
        subs = labels[:-2]

    return subs, root, suffix


def registrable_domain(host: str) -> str:
    subs, root, suffix = split_domain(host)
    if not root:
        return host
    return f"{root}.{suffix}" if suffix else root
