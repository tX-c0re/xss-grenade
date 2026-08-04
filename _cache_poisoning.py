"""
_cache_poisoning.py — web cache poisoning → stored XSS (v10.71).

Unkeyed input — request headers the CACHE does not include in its cache key but
the APP still reflects — turns a one-shot reflected bug into a STORED one served
to every user of that cache. The classic chain:

    GET /page  X-Forwarded-Host: evil.example
    → app builds <script src="//evil.example/app.js"> from the header
    → response is cacheable → the cache stores the poisoned copy
    → every subsequent visitor gets attacker-controlled markup = stored XSS

The tool already tests header reflection (inject_headers), but that does NOT
prove the reflection is CACHED and served back. This module confirms the full
chain and is safe by construction:

  1) CACHE-BUSTER — every probe uses a unique random query param so the poison
     can only ever land in OUR OWN throwaway cache entry, never a shared URL
     other users request. (Standard responsible methodology.)
  2) REFLECTION — an unkeyed header carrying a host-shaped `.invalid` marker
     must appear in the response (body or Location).
  3) CACHEABLE — the response must actually look cacheable (Cache-Control
     public/max-age>0 and not no-store/private, or a cache layer's own headers:
     Age / X-Cache / CF-Cache-Status / X-Varnish / X-Served-By).
  4) PERSISTENCE (the FP guard) — a follow-up request to the SAME busted URL
     WITHOUT the header must still return our marker. That proves the cache
     keyed on the URL but not the header — real poisoning. If it doesn't
     persist, it's mere header reflection (not our class) → dropped.

Severity tracks where the poisoned marker lands: a resource URL
(<script src>/<link href>/<base href>/<iframe src>) is worst (attacker host →
loaded code = XSS); a link/redirect is high; plain body is medium.

Public API:
    is_cacheable(resp_headers) -> bool
    scan_cache_poisoning(session, url, timeout, follow_redirects,
                         marker_factory) -> List[Dict]
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional

_NET_EXC = (Exception,)

# Unkeyed headers most commonly reflected into host/URL construction.
_UNKEYED_HEADERS = [
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
    "X-Forwarded-Server",
    "X-Host",
    "X-Forwarded-Port",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-HTTP-Host-Override",
    "Forwarded",
]

_CACHE_HINT_HEADERS = ("age", "x-cache", "cf-cache-status", "x-cache-hits",
                       "x-varnish", "x-served-by", "x-fastly", "x-nf-request-id")


def _hget(headers, name: str) -> str:
    """Case-insensitive header lookup that works on requests' CaseInsensitiveDict
    and on a plain dict."""
    if headers is None:
        return ""
    try:
        v = headers.get(name)
        if v is not None:
            return v
    except Exception:
        pass
    nl = name.lower()
    try:
        for k, v in headers.items():
            if k.lower() == nl:
                return v
    except Exception:
        pass
    return ""


def is_cacheable(resp_headers) -> bool:
    """Does the response look like something a shared cache would store?"""
    cc = _hget(resp_headers, "Cache-Control").lower()
    if "no-store" in cc or "private" in cc:
        return False
    if "public" in cc:
        return True
    m = re.search(r"max-age\s*=\s*(\d+)", cc)
    if m and int(m.group(1)) > 0:
        return True
    # A cache layer that stamps its own headers is itself the evidence.
    for hint in _CACHE_HINT_HEADERS:
        if _hget(resp_headers, hint):
            return True
    return False


def _cache_bust(url: str, token: str) -> str:
    sep = "&" if "?" in url else "?"
    return "%s%scb=%s" % (url, sep, token)


def _reflection_context(body: str, marker: str) -> Optional[str]:
    """Where did the poisoned marker land? Governs severity."""
    i = body.find(marker)
    if i < 0:
        return None
    pre = body[max(0, i - 160):i].lower()
    start = pre.rfind("<")
    tag = pre[start:] if start >= 0 else pre
    if (("script" in tag and "src" in tag) or ("base" in tag and "href" in tag)
            or ("link" in tag and "href" in tag) or ("iframe" in tag and "src" in tag)):
        return "resource-url"
    if "href=" in tag or "action=" in tag or "src=" in tag:
        return "link-url"
    return "body-text"


def _severity(where: str) -> str:
    return {"resource-url": "critical", "location": "high",
            "link-url": "high", "body-text": "medium"}.get(where, "medium")


def _emit(url: str, header: str, marker: str, where: str) -> Dict:
    sev = _severity(where)
    return {
        "url": url,
        "param": "%s (unkeyed header)" % header,
        "payload": "%s: %s" % (header, marker),
        "context": "cache-poisoning-%s" % where,
        "source": "cache-poisoning",
        "severity": sev,
        "cwe_hint": "CWE-524",
        "header": header,
        "reflection": where,
        "evidence": (
            "Unkeyed header %s reflected into a %s context AND persisted in a "
            "cacheable response served to a request WITHOUT the header — "
            "confirmed web cache poisoning." % (header, where)),
        "description": (
            "The response reflects the unkeyed request header %s and is cacheable; "
            "a follow-up request without the header still returned the injected "
            "value, so the cache keys on the URL but not the header. An attacker "
            "poisons the shared cache once and every subsequent visitor is served "
            "the attacker-controlled %s → stored XSS / redirect. Add the header to "
            "the cache key (Vary) or stop reflecting it; never build resource URLs "
            "from client-supplied host headers." % (header, where)),
    }


def scan_cache_poisoning(session, url: str, timeout: float,
                         follow_redirects: bool,
                         marker_factory: Callable[[], str]) -> List[Dict]:
    """Detect web cache poisoning at `url`. Returns engine-standard findings
    (one per confirmed unkeyed header). Safe: only ever poisons a unique
    cache-busted URL, and confirms via a clean follow-up request."""
    findings: List[Dict] = []
    seen_headers = set()

    for header in _UNKEYED_HEADERS:
        raw = marker_factory()
        token = marker_factory()
        marker = "xssg%s.invalid" % raw           # host-shaped, never resolves
        busted = _cache_bust(url, token)
        try:
            # ── poison the throwaway cache entry ──
            r = session.get(busted, headers={header: marker},
                            timeout=timeout, allow_redirects=False)
        except _NET_EXC:
            continue
        body = getattr(r, "text", "") or ""
        loc = _hget(getattr(r, "headers", {}), "Location")

        where = None
        if marker in body:
            where = _reflection_context(body, marker)
        elif marker in loc:
            where = "location"
        if where is None:
            continue                              # not reflected → skip

        if not is_cacheable(getattr(r, "headers", {})):
            continue                              # not cacheable → not our class

        # ── PERSISTENCE: clean request to the SAME busted URL, no header ──
        try:
            r2 = session.get(busted, timeout=timeout, allow_redirects=False)
        except _NET_EXC:
            continue
        body2 = getattr(r2, "text", "") or ""
        loc2 = _hget(getattr(r2, "headers", {}), "Location")
        persisted = (marker in body2) or (marker in loc2)
        if not persisted:
            continue                              # just header reflection → drop (FP guard)

        if header not in seen_headers:
            seen_headers.add(header)
            findings.append(_emit(url, header, marker, where))
    return findings
