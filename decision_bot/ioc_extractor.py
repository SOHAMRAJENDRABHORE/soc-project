"""
Extract indicators of compromise (IOCs) from raw alert text/JSON.

Pure regex, no LLM, no APIs. Deterministic and fast.

We deduplicate, filter out obvious noise (private IPs, common safe domains),
and tag each IOC with its type.
"""
from __future__ import annotations

import re
from ipaddress import ip_address, IPv4Address
from typing import Iterable

from shared.schemas import IOC, IOCType, Alert
from shared.logger import get_logger

log = get_logger(__name__)


# ----- Regex patterns -----

# IPv4 (we catch IPv6 too but skip private/multicast)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Domains: word chars, dots, dashes, ending in a known TLD-ish suffix
DOMAIN_RE = re.compile(
    r"\b(?=.{4,253}\b)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}\b"
)

# URLs
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

# Hashes (length-based detection)
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Emails
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")

# Windows file paths (e.g., C:\Users\... or \\share\...)
WIN_PATH_RE = re.compile(r"(?:[a-zA-Z]:\\|\\\\)[^\s\"'<>|*?]+", re.IGNORECASE)

# Unix file paths — only paths in suspicious locations, not system binaries
UNIX_PATH_RE = re.compile(r"(?:/(?:tmp|var/tmp|dev/shm|home|root|srv|mnt)/[^\s\"'<>]+)")

# Common command-line keywords that hint at suspicious activity
COMMAND_KEYWORDS = [
    "powershell", "cmd.exe", "wmic", "rundll32", "regsvr32",
    "mshta", "certutil", "bitsadmin", "schtasks", "wscript", "cscript",
    "/bin/sh", "/bin/bash", "curl ", "wget ", "nc ", "ncat ",
]

# Safe domain roots — we match these and all their subdomains
SAFE_DOMAIN_ROOTS = {
    "microsoft.com", "windows.com", "windowsupdate.com", "microsoftonline.com",
    "azure.com", "azureedge.net", "msftncsi.com", "office.com", "outlook.com",
    "live.com", "bing.com", "msn.com",
    "google.com", "googleapis.com", "gstatic.com", "googletagmanager.com",
    "cloudflare.com", "cloudfront.net",
    "amazon.com", "amazonaws.com", "awsstatic.com",
    "github.com", "githubusercontent.com",
    "apple.com", "icloud.com",
    "akamai.com", "akamaiedge.net", "akamaitechnologies.com",
    "digicert.com", "symantec.com", "verisign.com",
}

# TLDs that don't exist in real public DNS — internal/fake/OData suffixes
FAKE_TLDS = {
    "local", "internal", "corp", "lan", "intranet", "home", "invalid",
    "localhost", "test", "example",
    # OData/JSON-LD type pseudo-extensions seen in Microsoft Graph API responses
    "type", "evidence", "entities", "event", "alert", "incident",
}

# Prefixes that identify OData/API type strings, not real hostnames
ODATA_PREFIXES = ("microsoft.graph.", "odata.", "graph.microsoft.", "#microsoft.")


def _is_public_ip(s: str) -> bool:
    try:
        ip = ip_address(s)
        if not isinstance(ip, IPv4Address):
            return False
        return ip.is_global  # excludes private, loopback, multicast, etc.
    except ValueError:
        return False


def _is_safe_domain(d: str) -> bool:
    """Return True if d is a safe root domain or any subdomain of one."""
    for root in SAFE_DOMAIN_ROOTS:
        if d == root or d.endswith("." + root):
            return True
    return False


def _is_meaningful_domain(d: str) -> bool:
    d = d.lower().strip(".")
    # OData / Microsoft Graph API type strings (e.g. microsoft.graph.security.deviceevidence)
    if any(d.startswith(p) for p in ODATA_PREFIXES):
        return False
    # Safe vendor/infrastructure domains and their subdomains
    if _is_safe_domain(d):
        return False
    # Drop anything that's actually an IP caught by the domain regex
    if IPV4_RE.fullmatch(d):
        return False
    # Drop internal/non-routable TLDs and OData pseudo-TLDs
    tld = d.rsplit(".", 1)[-1].lower()
    if tld in FAKE_TLDS:
        return False
    # Drop common file extensions mistaken for domains (e.g. "report.docx")
    file_exts = {"exe", "dll", "docx", "xlsx", "pdf", "txt", "log", "zip", "msi",
                 "ps1", "bat", "vbs", "js", "py", "sh"}
    if tld in file_exts:
        return False
    # Drop very short labels that are likely JSON field names (e.g. "id.type")
    parts = d.split(".")
    if len(parts) < 2 or any(len(p) < 2 for p in parts):
        return False
    return True


def _is_safe_url(url: str) -> bool:
    """Return True if the URL's hostname belongs to a safe domain."""
    m = re.match(r"https?://([^/?\s#]+)", url, re.IGNORECASE)
    if not m:
        return False
    host = m.group(1).lower().split(":")[0]  # strip port
    return _is_safe_domain(host)


def _extract_command_lines(text: str) -> list[str]:
    """Find lines that look like suspicious commands."""
    found = []
    lower = text.lower()
    for kw in COMMAND_KEYWORDS:
        if kw in lower:
            # Grab a window of context around the keyword
            idx = lower.find(kw)
            start = max(0, idx - 20)
            end = min(len(text), idx + 200)
            snippet = text[start:end].strip()
            # Take just the line containing the keyword
            for line in snippet.splitlines():
                if kw in line.lower() and line.strip() not in found:
                    found.append(line.strip())
                    break
    return found


def extract_iocs(alert: Alert) -> list[IOC]:
    """
    Walk through the alert text and pull out every IOC we can find.
    Deduplicates by (type, value).
    """
    # Build one big searchable string from all alert fields
    parts: list[str] = []
    if alert.title:
        parts.append(alert.title)
    if alert.description:
        parts.append(alert.description)
    # Flatten the raw dict to a string so we catch IOCs nested inside it
    parts.append(_flatten(alert.raw))
    blob = "\n".join(parts)

    seen: set[tuple[IOCType, str]] = set()
    out: list[IOC] = []

    def add(t: IOCType, v: str, ctx: str = ""):
        key = (t, v.lower())
        if key in seen:
            return
        seen.add(key)
        out.append(IOC(type=t, value=v, context=ctx or None))

    # Hashes (check longest first so SHA256 isn't misread as SHA1+extra)
    for m in SHA256_RE.findall(blob):
        add(IOCType.HASH_SHA256, m, "hash")
    for m in SHA1_RE.findall(blob):
        # Skip if it's part of a SHA256 we already captured
        if any(m in s for _, s in seen):
            continue
        add(IOCType.HASH_SHA1, m, "hash")
    for m in MD5_RE.findall(blob):
        if any(m in s for _, s in seen):
            continue
        add(IOCType.HASH_MD5, m, "hash")

    # IPs
    for m in IPV4_RE.findall(blob):
        if _is_public_ip(m):
            add(IOCType.IP, m, "network")

    # URLs (extract before domains so we get the full URL)
    for m in URL_RE.findall(blob):
        u = m.rstrip(".,;:)")
        if not _is_safe_url(u):
            add(IOCType.URL, u, "network")

    # Domains
    for m in DOMAIN_RE.findall(blob):
        if _is_meaningful_domain(m):
            add(IOCType.DOMAIN, m.lower(), "network")

    # Emails
    for m in EMAIL_RE.findall(blob):
        add(IOCType.EMAIL, m, "identity")

    # File paths
    for m in WIN_PATH_RE.findall(blob):
        add(IOCType.FILE_PATH, m, "filesystem")
    for m in UNIX_PATH_RE.findall(blob):
        add(IOCType.FILE_PATH, m, "filesystem")

    # Command lines
    for cmd in _extract_command_lines(blob):
        add(IOCType.COMMAND_LINE, cmd, "process")

    log.info(f"Extracted {len(out)} IOCs from alert {alert.alert_id}")
    return out


def _flatten(obj, prefix: str = "") -> str:
    """Recursively flatten a dict/list into searchable text."""
    if isinstance(obj, dict):
        return " ".join(_flatten(v, k) for k, v in obj.items())
    if isinstance(obj, (list, tuple)):
        return " ".join(_flatten(v) for v in obj)
    return f"{prefix}={obj}" if prefix else str(obj)
