"""
_htmx_alpine.py — htmx / Alpine.js attribute-injection XSS (v10.69).

htmx and Alpine.js execute JavaScript straight from plain HTML attributes —
Alpine's  x-data / x-init / x-on:* / @click  and htmx's  hx-on::* — with NO
<script> tag and no on*= handler. When user input is reflected into an HTML
tag/attribute context on a page that loads one of these frameworks, an attacker
injects a framework attribute that the framework evaluates on load.

Why it matters (and why classic scanners miss it):
  • A CSP that forbids inline <script> and on*= event handlers does NOT stop
    x-init / hx-on — the page already had to permit the framework's own
    expression evaluation, so the injected attribute runs. (Honest nuance:
    Alpine/htmx expression eval needs script-src 'unsafe-eval'; sites that ship
    these frameworks already allow it, or run no CSP at all.)
  • Reflected/DOM XSS scanners look for <script> and on*= — a bare
    `x-data x-init="…"` or `hx-on::load="…"` sails straight past them.
  • htmx/Alpine are default in modern Django/Rails/Laravel starter stacks, so
    the surface is large and almost entirely untooled.

PRECISION (FP-guarded):
  1) FRAMEWORK GATE — the framework MUST be present on the page (its script
     include or its own attributes). No framework → no report. Primary FP guard.
  2) INJECTABLE CONTEXT — the marker must land where an ATTRIBUTE can be added
     (inside a tag, a quoted attribute value we break out of, or text where a
     fresh element survives).
  3) UNESCAPED SURVIVAL — the injected framework attribute must survive with its
     quotes / '<' intact. If the app entity-encodes the breakout → inert → drop.
  Optional: a headless `verify_exec(url, marker) -> bool` callback confirms the
  sentinel actually executes in a real browser (upgrades severity to critical).

Public API:
    detect_frameworks(body) -> set[str]            # subset of {'alpine','htmx'}
    html_attr_context(body, marker) -> str | None  # 'attr-double'|'attr-single'|'tag'|'text'
    scan_htmx_alpine(inject, session, url, param, timeout, follow_redirects,
                     marker_factory, verify_exec=None) -> List[Dict]
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Set

_NET_EXC = (Exception,)

# Framework fingerprints — script includes, JS globals, or their own attributes.
_ALPINE_RX = re.compile(
    r"(?:alpine(?:js)?(?:\.min)?\.js"
    r"|@alpinejs|/npm/alpinejs|unpkg\.com/alpinejs"
    r"|\bAlpine\.start\b|\bwindow\.Alpine\b"
    r"|\sx-data\b|\sx-init\b|\sx-show\b|\sx-bind\b|\sx-on:|\s@click\b)",
    re.IGNORECASE)
_HTMX_RX = re.compile(
    r"(?:htmx(?:\.org)?(?:\.min)?\.js"
    r"|/npm/htmx|unpkg\.com/htmx"
    r"|\bhtmx\.(?:process|ajax|config|onLoad)\b"
    r"|\shx-get\b|\shx-post\b|\shx-on:|\shx-on::|\shx-trigger\b|\shx-boost\b|\shx-swap\b)",
    re.IGNORECASE)


def _get(session, url: str, timeout: float, follow_redirects: bool) -> str:
    try:
        r = session.get(url, timeout=timeout, allow_redirects=follow_redirects)
        return r.text or ""
    except _NET_EXC:
        return ""


def detect_frameworks(body: str) -> Set[str]:
    """Which reactive-attribute frameworks the page loads. Subset of
    {'alpine','htmx'}. Empty set → the injection class does not apply."""
    out: Set[str] = set()
    if not body:
        return out
    if _ALPINE_RX.search(body):
        out.add("alpine")
    if _HTMX_RX.search(body):
        out.add("htmx")
    return out


def html_attr_context(body: str, marker: str) -> Optional[str]:
    """Where did the marker land, w.r.t. injecting an HTML attribute?
      'attr-double' — inside a "double-quoted" attribute value
      'attr-single' — inside a 'single-quoted' attribute value
      'tag'         — inside a tag but not in a quoted value (unquoted attr area)
      'text'        — in text/HTML body (outside any tag)
      None          — marker not found
    """
    if not body or marker not in body:
        return None
    i = body.find(marker)
    lt = body.rfind("<", 0, i)
    gt = body.rfind(">", 0, i)
    if lt > gt:
        # Between a '<' and its (not yet seen) '>' → inside a tag.
        seg = body[lt:i]
        if seg.count('"') % 2 == 1:
            return "attr-double"
        if seg.count("'") % 2 == 1:
            return "attr-single"
        return "tag"
    return "text"


def _framework_bits(fw: str, m: str):
    """(injected attribute string, unescaped-survival prefix, human label)."""
    if fw == "alpine":
        core = "x-data x-init=\"alert('%s')\"" % m
        prefix = "x-data x-init=\"alert('%s'" % m   # quotes MUST survive raw
        label = "Alpine.js x-init"
    else:  # htmx
        core = "hx-on::load=\"alert('%s')\"" % m
        prefix = "hx-on::load=\"alert('%s'" % m
        label = "htmx hx-on::load"
    return core, prefix, label


def _payload_and_needle(ctx: str, fw: str, m: str):
    """Build the context-appropriate payload + the exact substring that proves
    the framework attribute survived as REAL markup (not entity-encoded text)."""
    core, prefix, label = _framework_bits(fw, m)
    if ctx == "attr-double":
        payload = '%s"><span %s></span>' % (m, core)
        needle = "<span %s" % prefix
    elif ctx == "attr-single":
        payload = "%s'><span %s></span>" % (m, core)
        needle = "<span %s" % prefix
    elif ctx == "tag":
        # marker already inside a real tag → append attributes to it
        payload = "%s %s" % (m, core)
        needle = prefix
    else:  # text
        payload = "<span %s>%s</span>" % (core, m)
        needle = "<span %s" % prefix
    return payload, needle, label


def _emit(fw: str, url: str, param: str, payload: str, ctx: str, label: str,
          verified: Optional[bool]) -> Dict:
    sev = "critical" if verified else "high"
    note = ""
    if verified is True:
        note = " Execution CONFIRMED headless (sentinel fired)."
    elif verified is False:
        note = " Static breakout confirmed; headless did not observe exec."
    return {
        "url": url, "param": param, "payload": payload,
        "context": "htmx-alpine-%s-%s" % (fw, ctx),
        "source": "htmx-alpine",
        "severity": sev, "cwe_hint": "CWE-79",
        "framework": fw,
        "verified_exec": verified,
        "evidence": "%s attribute injected unescaped in %s context.%s" % (
            label, ctx, note),
        "description": (
            "User input is reflected into an HTML %s context on a page that "
            "loads %s, and an injected %s attribute survives unescaped. These "
            "frameworks evaluate JS straight from attributes (no <script>, no "
            "on*= handler), so this executes even under a CSP that only blocks "
            "inline scripts — and classic XSS scanners miss it. Context-encode "
            "the value (entity-encode \" ' < >) or reject it from HTML sinks." % (
                ctx, label.split()[0], label)),
    }


def scan_htmx_alpine(inject, session, url: str, param: str, timeout: float,
                     follow_redirects: bool,
                     marker_factory: Callable[[], str],
                     verify_exec: Optional[Callable[[str, str], bool]] = None
                     ) -> List[Dict]:
    """Detect htmx/Alpine attribute-injection XSS at (url, param).
    `inject` is the engine's inject_into_params(url, param, value). Returns
    engine-standard findings (possibly one per present framework)."""
    findings: List[Dict] = []

    # ── Step 1: reflect a plain marker, read the page ──
    probe = marker_factory()
    probe_url = inject(url, param, probe)
    if not probe_url:
        return findings
    body = _get(session, probe_url, timeout, follow_redirects)

    # ── Step 2: FRAMEWORK GATE (primary FP guard) ──
    fws = detect_frameworks(body)
    if not fws:
        return findings

    # ── Step 3: is the reflection in an attribute-injectable context? ──
    ctx = html_attr_context(body, probe)
    if ctx is None:
        return findings

    # ── Step 4: per framework, inject its attribute and confirm raw survival ──
    for fw in sorted(fws):
        m = marker_factory()
        payload, needle, label = _payload_and_needle(ctx, fw, m)
        test_url = inject(url, param, payload)
        if not test_url:
            continue
        body2 = _get(session, test_url, timeout, follow_redirects)
        if needle not in body2:
            continue  # breakout escaped/encoded → inert → drop (no FP)
        verified: Optional[bool] = None
        if verify_exec is not None:
            try:
                verified = bool(verify_exec(test_url, m))
            except Exception:
                verified = None
        findings.append(_emit(fw, test_url, param, payload, ctx, label, verified))
    return findings
