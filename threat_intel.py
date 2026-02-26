"""
threat_intel.py — Blocklist/allowlist and threat intelligence for industry-standard filtering.

- Sender domains can be blocklisted (always boost threat) or allowlisted (trusted, reduce threat).
- Loads from threat_intel.json in the project directory; optional DB table later.
- Used by inbox_scanner to align with industry practice of maintainable block/allow lists.
"""

import json
import os
from typing import List, Optional, Set, Tuple

_THREAT_INTEL_PATH = os.path.join(os.path.dirname(__file__), "threat_intel.json")
# Optional local override: add domains here (e.g. more Pakistani banks, local apps). Merged with main list.
_THREAT_INTEL_LOCAL_PATH = os.path.join(os.path.dirname(__file__), "threat_intel_local.json")
_blocklist: Optional[Set[str]] = None
_allowlist: Optional[Set[str]] = None


def _load_json_path(path: str) -> Tuple[Set[str], Set[str]]:
    out_b, out_a = set(), set()
    try:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            out_b = {d.lower().strip() for d in data.get("blocklist_domains", []) if d}
            out_a = {d.lower().strip() for d in data.get("allowlist_domains", []) if d}
    except Exception:
        pass
    return out_b, out_a


def _load_lists() -> Tuple[Set[str], Set[str]]:
    global _blocklist, _allowlist
    if _blocklist is not None and _allowlist is not None:
        return _blocklist, _allowlist
    _blocklist, _allowlist = _load_json_path(_THREAT_INTEL_PATH)
    # Merge local override (your banks, local apps) so you don't edit the main file
    local_b, local_a = _load_json_path(_THREAT_INTEL_LOCAL_PATH)
    _blocklist |= local_b
    _allowlist |= local_a
    return _blocklist, _allowlist


def check_sender_domain(domain: str) -> str:
    """
    Returns "blocklist" | "allowlist" | "none".
    Blocklist: domain (or parent) is in blocklist — treat as high-confidence threat.
    Allowlist: domain is in allowlist — treat as trusted (reduce false positives).
    """
    if not domain:
        return "none"
    domain = domain.lower().strip()
    block, allow = _load_lists()
    if domain in block:
        return "blocklist"
    if domain in allow:
        return "allowlist"
    # Subdomain: check if root is in list (e.g. evil.com → blocklist; mail.trusted.com → allowlist)
    for b in block:
        if domain == b or domain.endswith("." + b):
            return "blocklist"
    for a in allow:
        if domain == a or domain.endswith("." + a):
            return "allowlist"
    return "none"


def get_blocklist_allowlist_counts() -> Tuple[int, int]:
    """Return (len(blocklist), len(allowlist)) for UI/status."""
    b, a = _load_lists()
    return len(b), len(a)


def add_to_blocklist(domain: str) -> bool:
    """Add a domain to blocklist and persist. Returns True if file was updated."""
    global _blocklist
    b, a = _load_lists()
    domain = domain.lower().strip()
    if not domain or domain in a:
        return False
    b.add(domain)
    _blocklist = b
    return _persist(b, a)


def add_to_allowlist(domain: str) -> bool:
    """Add a domain to allowlist and persist."""
    global _allowlist
    b, a = _load_lists()
    domain = domain.lower().strip()
    if not domain:
        return False
    a.add(domain)
    _allowlist = a
    return _persist(b, a)


def add_to_allowlist_bulk(domains: List[str]) -> int:
    """Add multiple domains to allowlist and persist once. Returns count added."""
    global _allowlist
    b, a = _load_lists()
    added = 0
    for d in domains:
        d = (d or "").strip().lower()
        if d and "@" not in d and d not in a:
            a.add(d)
            added += 1
    _allowlist = a
    if added:
        _persist(b, a)
    return added


def remove_from_blocklist(domain: str) -> bool:
    """Remove a domain from blocklist and persist."""
    global _blocklist
    b, a = _load_lists()
    domain = domain.lower().strip()
    if domain not in b:
        return False
    b.discard(domain)
    _blocklist = b
    return _persist(b, a)


def remove_from_allowlist(domain: str) -> bool:
    """Remove a domain from allowlist and persist."""
    global _allowlist
    b, a = _load_lists()
    domain = domain.lower().strip()
    if domain not in a:
        return False
    a.discard(domain)
    _allowlist = a
    return _persist(b, a)


def reload_lists() -> None:
    """Force reload from disk (e.g. after external edit of threat_intel.json)."""
    global _blocklist, _allowlist
    _blocklist = None
    _allowlist = None
    _load_lists()


def get_lists() -> Tuple[List[str], List[str]]:
    """Return (sorted blocklist, sorted allowlist) for API/UI."""
    b, a = _load_lists()
    return sorted(b), sorted(a)


def _persist(block: Set[str], allow: Set[str]) -> bool:
    try:
        with open(_THREAT_INTEL_PATH, "w", encoding="utf-8") as f:
            json.dump({"blocklist_domains": sorted(block), "allowlist_domains": sorted(allow)}, f, indent=2)
        return True
    except Exception:
        return False
