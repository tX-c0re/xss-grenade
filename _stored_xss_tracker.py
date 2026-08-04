"""
_stored_xss_tracker.py
======================
Stored XSS round-trip detection — track canaries from POST/PUT requests
and hunt for them in subsequent re-crawl of all known endpoints.

Background
----------
Existing scanner posts canaries to forms and waits for response. If the
canary is in the response of the same POST, it's "reflected" (which is
already detected by reflexní fáze). But REAL stored XSS is different:

  1. POST /comment with canary
  2. Server stores comment in DB → response is just "OK"
  3. Later, ANOTHER user (or admin) loads /admin/comments
  4. Canary is rendered there → exec in admin context

The classic case never reflects in the same response. Existing scanner
misses it entirely.

What v9 does
------------
1. Per POST/PUT request, generate UNIQUE canary (XSGS_<random>) and
   register it: `canary → (origin_url, param, method, ts)`.
2. After all main scan phases finish, run a NEW phase: re-crawl all
   known endpoints + canonical admin paths (/admin, /dashboard, ...).
3. For each re-crawled response, search for ANY registered canary in
   the response body.
4. Match = CONFIRMED stored XSS:
     - origin_url where the canary was POSTed
     - reflection_url where it was found
     - severity = critical if reflection_url has admin/dashboard pattern,
       else high

Public API
----------

    StoredCanaryRegistry()
        Thread-safe dict canary → CanaryOrigin.

    make_stored_canary(prefix="XSGS") -> str
        Generate unique stored-canary token.

    hunt_canaries_in_response(html, registry, exclude_url=None)
        → List[StoredFinding] (matches found in this response).

    is_admin_path(url) -> bool
        Heuristic: does the URL look like admin/dashboard/profile?
"""

from __future__ import annotations

import random
import re
import string
import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

log = logging.getLogger("xss_grenade.stored_tracker")


# ──────────────────────────────────────────────────────────────────────────────
# DATA TYPES
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class CanaryOrigin:
    """Where this canary was originally injected."""
    url: str               # full URL of the POST/PUT
    param: str             # form field / json key / multipart name
    method: str            # POST / PUT / PATCH / etc.
    payload: str = ""      # full payload as sent (for diagnostic)
    ts: float = field(default_factory=time.time)


@dataclass
class StoredFinding:
    """One canary observed in a response that's NOT the origin URL."""
    canary: str
    origin: CanaryOrigin
    reflection_url: str    # URL where canary was found
    reflection_status: int = 0
    severity: str = "high"
    is_admin_context: bool = False
    snippet: str = ""      # ~150 chars of context around the canary

    @property
    def cross_origin(self) -> bool:
        """True if reflection_url is on a different host/path than origin."""
        try:
            o = urlparse(self.origin.url)
            r = urlparse(self.reflection_url)
            return (o.netloc != r.netloc) or (o.path != r.path)
        except Exception:
            return True


# ──────────────────────────────────────────────────────────────────────────────
# CANARY GENERATION
# ──────────────────────────────────────────────────────────────────────────────

# XSGS prefix to distinguish from:
#   XSGD = DOM v6 (dom_hooks_v6.js)
#   XSGV = Headless verifier (_headless_verifier.py)
#   XSGS = Stored (this module) ← v9
def make_stored_canary(prefix: str = "XSGS") -> str:
    """Generate unique stored-XSS canary token. Format: PREFIX_8RAND."""
    rnd = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
    return f"{prefix}_{rnd}"


# Pre-compiled match-all-canaries regex (any 4-letter PREFIX followed by 8 alnum)
_RE_CANARY = re.compile(
    r"\b(XSG[A-Z])_([A-Z0-9]{8})\b"
)


# ──────────────────────────────────────────────────────────────────────────────
# REGISTRY
# ──────────────────────────────────────────────────────────────────────────────

class StoredCanaryRegistry:
    """Thread-safe registry: canary → CanaryOrigin.

    Used by request manager (when canary is injected into POST body)
    and re-crawl hunter (when matching response bodies).
    """

    def __init__(self):
        self._d: Dict[str, CanaryOrigin] = {}
        self._lock = threading.Lock()

    def register(self, canary: str, origin: CanaryOrigin) -> None:
        with self._lock:
            self._d[canary] = origin

    def get(self, canary: str) -> Optional[CanaryOrigin]:
        with self._lock:
            return self._d.get(canary)

    def all_canaries(self) -> List[str]:
        with self._lock:
            return list(self._d.keys())

    def __len__(self) -> int:
        with self._lock:
            return len(self._d)

    def __contains__(self, canary: str) -> bool:
        with self._lock:
            return canary in self._d


# ──────────────────────────────────────────────────────────────────────────────
# ADMIN PATH DETECTION
# ──────────────────────────────────────────────────────────────────────────────

# URL path patterns that suggest admin/sensitive context — boost severity
# to CRITICAL when canary lands here.
_ADMIN_PATTERNS = [
    re.compile(r"/admin\b", re.I),
    re.compile(r"/administrator\b", re.I),
    re.compile(r"/dashboard\b", re.I),
    re.compile(r"/manage\b", re.I),
    re.compile(r"/settings\b", re.I),
    re.compile(r"/profile\b", re.I),
    re.compile(r"/account\b", re.I),
    re.compile(r"/console\b", re.I),
    re.compile(r"/control\b", re.I),
    re.compile(r"/staff\b", re.I),
    re.compile(r"/moderator\b", re.I),
    re.compile(r"/wp-admin\b", re.I),
    re.compile(r"/cms\b", re.I),
    re.compile(r"/backend\b", re.I),
]


def is_admin_path(url: str) -> bool:
    """Heuristic: does URL path suggest admin/sensitive context?"""
    try:
        path = urlparse(url).path or "/"
    except Exception:
        return False
    return any(pat.search(path) for pat in _ADMIN_PATTERNS)


# Common admin paths to PROBE during re-crawl even if they weren't in
# crawled `pages` list. Helps catch stored XSS where attacker can't
# directly access admin but admin will see the content later.
COMMON_ADMIN_PROBE_PATHS = [
    "/admin/", "/admin", "/administrator/", "/dashboard/", "/wp-admin/",
    "/manage/", "/console/", "/cms/", "/backend/", "/staff/",
]


# ──────────────────────────────────────────────────────────────────────────────
# CANARY HUNTING IN RESPONSES
# ──────────────────────────────────────────────────────────────────────────────

def hunt_canaries_in_response(
    response_text: str,
    response_url: str,
    registry: StoredCanaryRegistry,
    exclude_origin: bool = True,
    response_status: int = 200,
    is_recrawl_phase: bool = False,
) -> List[StoredFinding]:
    """Search response body for any registered stored canary.

    Args:
        response_text: HTML / JSON / text body of the response
        response_url: URL the response came from
        registry: StoredCanaryRegistry with all known canaries
        exclude_origin: if True, skip matches that are merely the
                        injection being reflected back in the SAME
                        response (covered by the reflexní fáze)
        response_status: HTTP status of the response
        is_recrawl_phase: True when this body comes from a LATER,
                        separate request (the re-crawl hunt), not from
                        the response to the injection itself.

    Returns:
        List of StoredFinding, one per unique (canary, response_url) match.

    v10.14 fix — same-URL stored XSS:
        Previously exclude_origin skipped ANY match where
        reflection_url == origin_url, calling it "reflected". That is
        WRONG: a guestbook / profile / settings / article-comment page
        where POST and GET share one URL is the textbook stored-XSS
        shape (POST writes to DB, a LATER GET renders it from DB).
        Same URL does not mean reflected — reflected means the canary
        came back in the response to the injecting request itself.
        During the re-crawl phase (is_recrawl_phase=True) a separate
        later request is BY DEFINITION not that — so URL equality is
        no longer a reason to skip. The only true exclusion is a
        canary echoed in the immediate response to its own injection,
        which is what the reflexní fáze already reports.
    """
    findings: List[StoredFinding] = []
    if not response_text or not registry:
        return findings

    # v10.80 FN fix: match the ACTUAL registered canaries as substrings of the
    # body. The old code tokenized via _RE_CANARY (XSG?_<8 UPPER>) then dict-get,
    # but the stored phase plants markers of a DIFFERENT shape ("SXSS…" base +
    # per-field suffix), so nothing ever matched and the whole round-trip layer
    # was inert (logged n_canaries>0 then always "0 findings"). Substring search
    # over the (small) registry is format-agnostic, finds exactly the canaries WE
    # planted, and still ignores unrelated XSGD/XSGV markers (never registered).
    seen_in_this_response: Set[str] = set()
    for full in registry.all_canaries():
        if full in seen_in_this_response:
            continue   # report each canary once per response
        idx = response_text.find(full)
        if idx < 0:
            continue
        origin = registry.get(full)
        if origin is None:
            continue
        # Exclusion applies ONLY outside the re-crawl phase. Outside
        # re-crawl, a canary on the SAME URL as the origin is the
        # injection echoed back in the response to the injecting
        # request itself = reflected (the reflexní fáze reports it),
        # regardless of method. During the re-crawl phase
        # (is_recrawl_phase=True, set explicitly by the engine) the
        # body comes from a LATER separate request, so a canary that
        # was POSTed and now appears — even on the same URL — is
        # stored XSS (guestbook / profile / comments pattern) and is
        # NEVER excluded here.
        if exclude_origin and not is_recrawl_phase:
            try:
                o_parsed = urlparse(origin.url)
                r_parsed = urlparse(response_url)
                same_url = (o_parsed.netloc == r_parsed.netloc
                            and o_parsed.path == r_parsed.path)
                if same_url:
                    continue
            except Exception:
                pass
        seen_in_this_response.add(full)

        # Snippet around match for diagnostic
        start = max(0, idx - 60)
        end = min(len(response_text), idx + len(full) + 60)
        snippet = response_text[start:end].replace("\n", " ")[:200]

        # Severity: admin context = critical
        is_admin = is_admin_path(response_url)
        sev = "critical" if is_admin else "high"

        findings.append(StoredFinding(
            canary=full,
            origin=origin,
            reflection_url=response_url,
            reflection_status=response_status,
            severity=sev,
            is_admin_context=is_admin,
            snippet=snippet,
        ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# CONVENIENCE: per-test canary generation with auto-register
# ──────────────────────────────────────────────────────────────────────────────

def make_and_register(
    registry: StoredCanaryRegistry,
    url: str,
    param: str,
    method: str = "POST",
    payload: str = "",
) -> str:
    """Generate canary AND register it in one call. Returns the canary token.

    Use in request building code:
        canary = make_and_register(registry, url, "comment", payload="<svg/onload=alert(1)>")
        body = body.replace("CANARY_PLACEHOLDER", canary)
    """
    canary = make_stored_canary()
    registry.register(canary, CanaryOrigin(
        url=url, param=param, method=method, payload=payload,
    ))
    return canary
