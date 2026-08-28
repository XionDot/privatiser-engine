"""Network-related patterns: IP addresses, domains, emails, MAC addresses."""

import re

from . import PatternHandler, register

# IPs that are meaningful and should NOT be anonymized
SKIP_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "::1", "::"}

# Domains to never anonymize (cloud provider / common infra domains)
SKIP_DOMAINS = {
    "amazonaws.com", "aws.amazon.com", "azure.com",
    "googleapis.com", "google.com", "cloudflare.com",
    "terraform.io", "hashicorp.com", "github.com",
    "docker.io", "docker.com", "gcr.io", "ghcr.io",
    "example.com", "example.org", "example.net",
    "googleusercontent.com",
}


def _ip_validator(match: re.Match) -> bool:
    """Skip well-known IPs."""
    raw = match.group(0)
    ip = raw.rsplit("/", 1)[0] if "/" in raw else raw
    return ip not in SKIP_IPS


def _ip_transform(match: re.Match) -> tuple[str, str]:
    """Split CIDR suffix so only the IP part gets mapped."""
    raw = match.group(0)
    if "/" in raw:
        ip, cidr = raw.rsplit("/", 1)
        return ip, ""  # cidr handled in pseudonym_fn via post-processing
    return raw, ""


def _ip_pseudonym(n: int) -> str:
    return f"10.{(n // 256) % 256}.{n % 256}.{(n * 7) % 254 + 1}"


def _domain_validator(match: re.Match) -> bool:
    """Skip cloud provider and common infra domains."""
    original = match.group(0)
    for skip in SKIP_DOMAINS:
        if original.endswith(skip) or original == skip:
            return False
    return True


register(
    # Private/internal URLs with non-standard ports
    PatternHandler(
        name="private_url",
        category="url",
        regex=re.compile(
            r"https?://[a-zA-Z0-9.\-]+:[1-9]\d{2,4}"
            r"(?:/[^\s\"'`\]}>)]*)?",
        ),
        pseudonym_fn=lambda n: f"http://redacted-internal-{n}.local:8080",
        priority=35,
    ),

    # IPv4 with optional CIDR
    PatternHandler(
        name="ipv4",
        category="ip",
        regex=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
            r"(?:/\d{1,2})?\b"
        ),
        pseudonym_fn=_ip_pseudonym,
        priority=60,
        validator=_ip_validator,
    ),

    # Email addresses
    PatternHandler(
        name="email",
        category="email",
        regex=re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        pseudonym_fn=lambda n: f"user-{n}@redacted.example.net",
        priority=55,
    ),

    # Domain names
    PatternHandler(
        name="domain",
        category="domain",
        regex=re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
            r"+(?:com|org|net|io|dev|co|app|cloud|internal|local|corp)\b"
        ),
        pseudonym_fn=lambda n: f"redacted-host-{n}.example.net",
        priority=70,
        validator=_domain_validator,
    ),

    # MAC addresses
    PatternHandler(
        name="mac_address",
        category="mac",
        regex=re.compile(
            r"\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
        ),
        pseudonym_fn=lambda n: f"AA:BB:CC:00:00:{n % 256:02X}",
        priority=50,
    ),
)
