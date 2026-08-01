"""DOMPurify CVE feed — data-driven version vulnerability matching.

Replaces hardcoded `if 3.0.1 <= version < 3.4.0` check in PP module with
a maintainable feed that can grow as new CVEs are published by Cure53.

Update strategy:
  - Quarterly review of GitHub Security Advisories for cure53/DOMPurify
  - Each new CVE adds entry here, no engine code changes
  - `match_cves_for_version()` returns ALL matching CVEs for a given version

Sources:
  - https://github.com/cure53/DOMPurify/security/advisories
  - https://nvd.nist.gov/vuln/search?query=DOMPurify
"""

from typing import Dict, List, Optional, Tuple


# ── CVE feed entries ──────────────────────────────────────────────────────────
# Each entry MUST have:
#   cve              — Official CVE ID
#   min_version      — First vulnerable version (inclusive)
#   max_version      — First patched version (exclusive)
#   severity         — critical / high / medium
#   vector           — Short attack vector classification
#   description      — One-line summary
#   bypass_payload   — Example PoC payload (for report value)
#   reference        — Primary reference URL (advisory or writeup)

DOMPURIFY_CVE_FEED: List[Dict] = [
    {
        "cve": "CVE-2024-47875",
        "min_version": "3.0.0",
        "max_version": "3.1.7",       # patched in 3.1.7
        "severity": "high",
        "vector": "mxss-svg-namespace",
        "description": (
            "mXSS via SVG namespace confusion — nested SVG elements bypass "
            "ALLOWED_TAGS check during sanitization re-parse"
        ),
        "bypass_payload": (
            '<svg></p><style><a id="</style><img src=x onerror=alert(1)>"></a>'
        ),
        "reference": (
            "https://github.com/cure53/DOMPurify/security/advisories/"
            "GHSA-mmhx-hmjr-r674"
        ),
    },
    {
        "cve": "CVE-2025-26791",
        "min_version": "3.0.0",
        "max_version": "3.2.4",       # patched in 3.2.4
        "severity": "high",
        "vector": "template-literal-escape",
        "description": (
            "Template literal escape — backtick characters bypass HTML "
            "sanitization when content re-rendered in template engine"
        ),
        "bypass_payload": "${alert(1)}",
        "reference": (
            "https://github.com/cure53/DOMPurify/security/advisories/"
            "GHSA-vhxf-7vqr-mrjg"
        ),
    },
    {
        "cve": "CVE-2026-41238",
        "min_version": "3.0.1",
        "max_version": "3.4.0",       # patched in 3.4.0
        "severity": "critical",
        "vector": "prototype-pollution-bypass",
        "description": (
            "Prototype pollution allows bypassing CUSTOM_ELEMENT_HANDLING — "
            "polluted Object.prototype overrides DOMPurify config at sanitize() time"
        ),
        "bypass_payload": (
            'Object.prototype.ALLOWED_TAGS=["script"]; '
            'DOMPurify.sanitize("<script>alert(1)</script>")'
        ),
        "reference": (
            "https://github.com/cure53/DOMPurify/security/advisories/"
            "GHSA-9p3r-4748-89cv"
        ),
    },
    # v10.16 (ověřeno přes web 2026-05): rawtext-element SAFE_FOR_XML
    # bypassy — útočník zavře rawtext kontext (</textarea>, </noscript>…)
    # uvnitř hodnoty atributu a vyláme se z něj.
    {
        "cve": "CVE-2025-15599",
        "min_version": "3.1.3",
        "max_version": "3.2.7",       # 3.x patched in 3.2.7; 2.x NEVER patched
        "severity": "medium",
        "vector": "rawtext-textarea-bypass",
        "description": (
            "Attribute sanitization bypass — missing <textarea> rawtext "
            "validation in SAFE_FOR_XML regex. Closing rawtext tags like "
            "</textarea> inside attribute values break out of rawtext "
            "context and execute JS when output is placed in a rawtext "
            "element. 2.x branch (2.5.3–2.5.8) never patched."
        ),
        "bypass_payload": (
            '<textarea><x title="</textarea><img src=x onerror=alert(1)>">'
        ),
        "reference": (
            "https://github.com/cure53/DOMPurify/security/advisories/"
            "GHSA-4r46-2hf2-h5gx"
        ),
    },
    {
        "cve": "CVE-2026-0540",
        "min_version": "3.1.3",
        "max_version": "3.3.2",       # fixed commit 2726c74 (after 3.3.1)
        "severity": "medium",
        "vector": "rawtext-elements-bypass",
        "description": (
            "Attribute sanitization bypass via five missing rawtext "
            "elements (noscript, xmp, noembed, noframes, iframe) in the "
            "SAFE_FOR_XML regex. Payloads like "
            "'</noscript><img src=x onerror=alert(1)>' in attribute values "
            "escape sanitization. 2.x (2.5.3–2.5.8) unpatched."
        ),
        "bypass_payload": (
            '<noscript><x title="</noscript><img src=x onerror=alert(1)>">'
        ),
        "reference": (
            "https://github.com/cure53/DOMPurify/security/advisories/"
            "GHSA-rp65-9cf3-cjxr"
        ),
    },
]


def _parse_semver(ver: Optional[str]) -> Optional[Tuple[int, int, int, int]]:
    """Parse 'X.Y.Z' string to a comparable tuple. Returns None if unparseable.

    Tolerant to '3.0' (assumes patch=0) and '3.0.1-beta' (pre-release).
    The 4th element encodes SemVer pre-release ordering: a pre-release sorts
    BEFORE its final release (0 < 1), so '3.4.0-beta' < '3.4.0'. Without this,
    a pre-release of the FIXED (max_version) release parses equal to the fix and
    is wrongly treated as patched — a false negative at the upper boundary.
    Build metadata ('+build') does NOT affect precedence (per SemVer).
    """
    if not ver:
        return None
    core = ver.split("+")[0].strip()          # drop build metadata (no precedence)
    is_prerelease = "-" in core               # e.g. 3.4.0-beta
    clean = core.split("-")[0].strip()
    parts = clean.split(".")
    try:
        nums = [int(p) for p in parts[:3]]
    except ValueError:
        return None
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2], 0 if is_prerelease else 1)


def _version_in_range(ver: str, min_ver: str, max_ver: str) -> bool:
    """Check if min_ver <= ver < max_ver (semantic ordering)."""
    v = _parse_semver(ver)
    lo = _parse_semver(min_ver)
    hi = _parse_semver(max_ver)
    if not (v and lo and hi):
        return False
    return lo <= v < hi


def match_cves_for_version(version: Optional[str]) -> List[Dict]:
    """Return list of CVE dicts that affect the given DOMPurify version.

    Empty list if version is None, unparseable, or in safe range.
    Returns DEEP COPIES so caller can mutate without affecting feed.
    """
    if not version:
        return []
    matched: List[Dict] = []
    for entry in DOMPURIFY_CVE_FEED:
        if _version_in_range(version, entry["min_version"], entry["max_version"]):
            matched.append(dict(entry))  # shallow copy is enough — feed is flat
    return matched


def is_vulnerable_version(version: Optional[str]) -> bool:
    """Backward-compat shortcut: True if version matches ANY CVE in feed.

    Used by older code paths that just need a yes/no on vulnerability status.
    """
    return bool(match_cves_for_version(version))


def cve_summary(version: Optional[str]) -> str:
    """Human-readable summary of vulnerabilities for given version.

    Returns e.g. "CVE-2024-47875 (high) + CVE-2025-26791 (high)" or "safe".
    """
    matches = match_cves_for_version(version)
    if not matches:
        return "safe"
    return " + ".join(f"{m['cve']} ({m['severity']})" for m in matches)


# ── Stats helpers (for engine logging) ────────────────────────────────────────

def feed_size() -> int:
    """Number of CVE entries in feed (for log messages)."""
    return len(DOMPURIFY_CVE_FEED)


def feed_cve_list() -> List[str]:
    """List of all CVE IDs in feed (for documentation / debug)."""
    return [e["cve"] for e in DOMPURIFY_CVE_FEED]
