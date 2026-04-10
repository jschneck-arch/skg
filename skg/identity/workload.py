"""
skg.identity.workload
=====================
Canonical workload ID builder.

Single source of truth for converting any raw target identifier into
a deterministic, domain-prefixed workload ID.

All adapters and sensors must use canonical_workload_id() when emitting
events. This prevents the identity fragmentation where the same physical
target appears as six different keys in the engagement database.

Supported input shapes (all normalize to the same canonical form):
  "192.168.1.5"              → "host::192.168.1.5"
  "nmap::192.168.1.5"        → "host::192.168.1.5"
  "ssh::192.168.1.5"         → "host::192.168.1.5"
  "msf::sess::192.168.1.5"   → "host::192.168.1.5"
  "msf_workspace"            → "host::msf_workspace" (best-effort)
  "http://192.168.1.5/dvwa"  → "web::192.168.1.5"   (with domain="web")
  "web::192.168.1.5"         → "web::192.168.1.5"   (idempotent)
"""
from __future__ import annotations

from urllib.parse import urlparse

# Domain prefixes that are valid and should not be treated as raw IPs
_VALID_DOMAIN_PREFIXES = {
    "host", "web", "ssh", "ad_lateral", "data", "data_pipeline",
    "binary", "binary_analysis", "container_escape", "supply_chain",
    "iot_firmware", "metacognition", "ai_target", "aprs",
}


def _extract_host(raw: str) -> str:
    """Extract the bare hostname or IP from any identifier shape."""
    text = str(raw or "").strip()
    if not text:
        return ""

    # Full URL: http://192.168.1.5/path → 192.168.1.5
    if "://" in text:
        try:
            return urlparse(text).hostname or text
        except Exception:
            pass

    # domain::locator — strip known prefixes recursively until bare host remains
    if "::" in text:
        parts = text.split("::", 1)
        prefix = parts[0].lower()
        rest = parts[1]
        if prefix in _VALID_DOMAIN_PREFIXES or prefix in ("nmap", "msf", "msfconsole"):
            # Recurse: msf::sess::192.168.1.5 → sess::192.168.1.5 → 192.168.1.5
            return _extract_host(rest)
        # Unknown prefix — treat the whole thing as the locator
        return _extract_host(rest)

    # host:port → just the host
    if text.count(":") == 1 and "." in text:
        return text.split(":", 1)[0]

    return text


def canonical_workload_id(raw: str, domain: str = "host") -> str:
    """
    Return a canonical domain-prefixed workload ID.

    Parameters
    ----------
    raw : str
        Any workload identifier: bare IP, URL, prefixed form, or raw string.
    domain : str
        Target domain. Defaults to "host". Use "web" for web targets.

    Returns
    -------
    str
        Canonical form: ``"{domain}::{identity_key}"``.
        Idempotent: calling twice with the same domain returns the same string.
    """
    text = str(raw or "").strip()
    if not text:
        return f"{domain}::unknown"

    # Already canonical for the requested domain — idempotent fast path
    if text.startswith(f"{domain}::"):
        # Verify the rest is not itself a prefixed form (e.g. host::nmap::ip)
        suffix = text[len(domain) + 2:]
        if "::" not in suffix or suffix.split("::", 1)[0] not in _VALID_DOMAIN_PREFIXES:
            return text

    # Lazy import to avoid circular dependency (workload.py ← identity/__init__.py)
    from skg.identity import parse_workload_ref  # noqa: PLC0415
    parsed = parse_workload_ref(text)
    host = str(parsed.get("host") or "").strip()

    # parse_workload_ref may return an intermediate token (e.g. "sess" from
    # "msf::sess::192.168.1.5") instead of the actual host.  Fall back to
    # _extract_host whenever the result looks like a non-address token: no
    # dots (so not an IP or FQDN), or the original input contained further
    # compound prefixes that _host_from_locator didn't strip fully.
    _looks_like_addr = host and ("." in host or ":" in host)  # IPv4/IPv6/FQDN
    if not host or host == text or "::" in host or not _looks_like_addr:
        host = _extract_host(text)

    identity_key = host or text
    return f"{domain}::{identity_key}"
