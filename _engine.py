"""
_engine.py
==========
Main orchestration: analyze() pulls HTML + JS + URL analyzers together
and produces a ReflectionContext.

Also houses the sanitization / executability gate — given a
ReflectionContext and a raw payload, decides whether the payload's
breakout-required characters actually made it through un-escaped.
"""

from __future__ import annotations

import logging
import re
from html import escape as html_escape
from typing import Optional, Set, Tuple, List

from context_engine import (  # type: ignore[import-not-found]
    Context, SubContext, Severity, Evidence, ReflectionContext,
    _compute_breakout, _compute_severity,
)
from _html_analyzer import analyze_html, _HtmlLocation   # type: ignore
from _js_analyzer import analyze_js                       # type: ignore
from _url_analyzer import classify_url_subcontext         # type: ignore

log = logging.getLogger("context_engine.engine")


# ══════════════════════════════════════════════════════════════════════════════
# SNIPPET HELPER
# ══════════════════════════════════════════════════════════════════════════════

def _snippets(body: str, off: int, width: int = 80) -> Tuple[str, str]:
    before = body[max(0, off - width):off]
    after  = body[off:min(len(body), off + width)]
    return before, after


# ══════════════════════════════════════════════════════════════════════════════
# SANITIZATION GATE
# ══════════════════════════════════════════════════════════════════════════════

# Map raw breakout char → its common encoded forms
_ENCODED_FORMS = {
    "<":  ["&lt;", "&LT;", "&#60;", "&#x3c;", "&#x3C;", "%3C", "%3c",
            "\\u003c", "\\u003C", "\\x3c", "\\x3C"],
    ">":  ["&gt;", "&GT;", "&#62;", "&#x3e;", "&#x3E;", "%3E", "%3e",
            "\\u003e", "\\u003E", "\\x3e", "\\x3E"],
    '"':  ['&quot;', '&QUOT;', '&#34;', '&#x22;', "%22",
            '\\"', '\\u0022', '\\x22'],
    "'":  ["&#39;", "&#x27;", "&apos;", "%27",
            "\\'", "\\u0027", "\\x27"],
    "/":  ["&#47;", "&#x2f;", "&#x2F;", "%2F", "%2f"],
    "=":  ["&#61;", "&#x3d;", "&#x3D;", "%3D", "%3d"],
    "`":  ["&#96;", "&#x60;", "%60", "\\u0060", "\\x60"],
    "(":  ["&#40;", "&#x28;", "%28"],
    ")":  ["&#41;", "&#x29;", "%29"],
    "{":  ["&#123;", "&#x7b;", "&#x7B;", "%7B", "%7b"],
    "}":  ["&#125;", "&#x7d;", "&#x7D;", "%7D", "%7d"],
    ":":  ["&#58;", "&#x3a;", "&#x3A;", "%3A", "%3a"],
    ";":  ["&#59;", "&#x3b;", "&#x3B;", "%3B", "%3b"],
    "-":  ["&#45;", "&#x2d;", "&#x2D;", "%2D", "%2d"],
    "*":  ["&#42;", "&#x2a;", "&#x2A;", "%2A", "%2a"],
    " ":  ["&nbsp;", "&#32;", "&#x20;", "%20", "+"],
    "\n": ["%0A", "%0a", "\\n", "&#10;"],
}


def _payload_required_chars(payload: str) -> Set[str]:
    """Extract the interesting syntactic chars from a payload."""
    interesting = set("<>\"'`/=(){};:-*")
    return {c for c in payload if c in interesting}


def _js_char_unescaped(s: str, idx: int, ch: str) -> bool:
    """For a JS quote/backtick at s[idx], is it NOT backslash-escaped? An even
    number of preceding backslashes → the quote really closes the string. Chars
    that can't be backslash-neutralised (<, >, /, =) are always 'raw'."""
    if ch not in ('"', "'", '`'):
        return True
    n = 0
    j = idx - 1
    while j >= 0 and s[j] == "\\":
        n += 1
        j -= 1
    return (n % 2) == 0


def _side_is_raw(full_body: str, base_off: int, side_text: str, ch: str,
                 anchor_at_end: bool) -> bool:
    """`side_text` is the payload segment reflected VERBATIM adjacent to the
    marker (anchor_at_end=True → it ends at base_off; False → starts at base_off).
    True iff `ch`'s reflected occurrence is genuinely raw (and, for a JS quote,
    unescaped) — so page chrome and backslash-escaped quotes don't count."""
    if not side_text or ch not in side_text:
        return False
    if anchor_at_end:
        start = base_off - len(side_text)
        rel = side_text.rfind(ch)
    else:
        start = base_off
        rel = side_text.find(ch)
    abs_idx = start + rel
    if abs_idx < 0 or abs_idx >= len(full_body):
        return False
    return _js_char_unescaped(full_body, abs_idx, ch)


def _count_unescaped(win: str, ch: str) -> int:
    """Count occurrences of `ch`, skipping backslash-escaped JS quotes."""
    if ch not in ('"', "'", '`'):
        return win.count(ch)
    return sum(1 for i, c in enumerate(win)
               if c == ch and _js_char_unescaped(win, i, ch))


def check_executability(body: str, marker_off: int, payload: str,
                         breakout_required: Set[str],
                         window: int = 250,
                         marker: str = "") -> Tuple[bool, float, List[str]]:
    """
    Given the context's required breakout chars and the raw response body,
    return (is_executable, confidence, notes).

    Rules:
        - If payload didn't contain any of the breakout chars at all, the
          payload is inert in this context — not executable, but also not
          "escaped" (just wrong bank). Confidence returned accordingly.
        - For each required char:
              * present raw in window → OK
              * present only as encoded form → sanitized
              * not present at all → depends on payload
        - is_executable = True iff at least one raw breakout char is
          present in the window AND at least one breakout-required char
          that the payload tries to emit is raw (not fully encoded).
    """
    notes: List[str] = []
    start = max(0, marker_off - window)
    end   = min(len(body), marker_off + window)
    win   = body[start:end]

    # What breakout chars does the payload actually try to emit?
    payload_chars = _payload_required_chars(payload)
    if not breakout_required:
        # The context has no breakout requirement (e.g. event_handler / exec)
        # → payload is inherently executable here.
        return True, 1.0, ["no_breakout_required"]

    payload_breakouts = payload_chars & breakout_required
    if not payload_breakouts:
        notes.append(f"payload_has_no_breakout_chars_for_ctx "
                     f"needed={sorted(breakout_required)} "
                     f"got={sorted(payload_chars)}")
        # Payload can't escape this context → not a vulnerability for this
        # payload, but the context is still valid for other payloads.
        return False, 0.4, notes

    raw_present = []
    encoded_only = []

    # v10.78 FP fix: judge raw-vs-escaped from the PAYLOAD's OWN reflected chars,
    # aligned to the marker — NOT a wide window that also counts the page's own
    # <p>/<div> tags (HTML-escaped-reflection FP) or a backslash-escaped JS quote
    # (script-context FP). Only when the reflection can't be aligned verbatim do
    # we fall back to a window scan (now skipping backslash-escaped quotes).
    marker_here = bool(marker) and body[marker_off:marker_off + len(marker)] == marker
    mp = payload.find(marker) if (marker_here and payload) else -1
    aligned = False
    if mp >= 0:
        before = payload[:mp]
        after = payload[mp + len(marker):]
        m_end = marker_off + len(marker)
        b_ok = bool(before) and body[:marker_off].endswith(before)
        a_ok = bool(after) and body[m_end:].startswith(after)
        b_esc = (not b_ok) and bool(before) and \
            body[:marker_off].endswith(html_escape(before))
        a_esc = (not a_ok) and bool(after) and \
            body[m_end:].startswith(html_escape(after))
        if b_ok or a_ok or b_esc or a_esc:
            aligned = True
            for ch in payload_breakouts:
                raw = ((ch in before and b_ok and
                        _side_is_raw(body, marker_off, before, ch, True))
                       or (ch in after and a_ok and
                           _side_is_raw(body, m_end, after, ch, False)))
                if raw:
                    raw_present.append(ch)
                elif ((ch in before and (b_ok or b_esc))
                      or (ch in after and (a_ok or a_esc))):
                    # reflected verbatim-but-escaped (JS backslash quote) or
                    # entity-encoded (HTML) → sanitized for this char
                    encoded_only.append(ch)

    if not aligned:
        for ch in payload_breakouts:
            raw_count = _count_unescaped(win, ch)
            encoded_count = sum(win.count(enc) for enc in _ENCODED_FORMS.get(ch, []))
            if raw_count > 0:
                raw_present.append(ch)
            elif encoded_count > 0:
                encoded_only.append(ch)

    if raw_present:
        conf = len(raw_present) / max(1, len(payload_breakouts))
        notes.append(f"raw_breakouts_present={raw_present}")
        return True, min(1.0, 0.5 + 0.5 * conf), notes

    if encoded_only:
        notes.append(f"all_breakouts_encoded={encoded_only}")
        return False, 0.95, notes

    notes.append("breakout_chars_absent_from_window")
    return False, 0.5, notes


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def analyze(body: str,
            marker: str,
            payload: Optional[str] = None) -> ReflectionContext:
    """
    Locate `marker` (or `payload` as fallback) in `body` and return a
    fully-populated ReflectionContext.

    Returns a ReflectionContext with context=UNKNOWN, confidence=0.0 if
    the marker cannot be found at all.

    If `payload` is supplied and its breakout chars are fully encoded
    in the vicinity of the reflection, the returned context is
    HTML_ESCAPED regardless of where the reflection landed.
    """
    if not body or not marker:
        return ReflectionContext()

    # ─── 1. Locate ALL reflection offsets (marker preferred, payload fallback) ─
    # v10.82 DEPTH: a parameter often reflects MORE THAN ONCE — e.g. once safely
    # inside a JS string literal AND once as raw HTML text. Classifying only the
    # FIRST occurrence locked onto whichever came first (frequently the safe one)
    # and never probed the exploitable reflection elsewhere on the page. Collect
    # every occurrence (capped for cost), classify each, and return the most
    # dangerous by (executability, severity) — executability primary.
    def _find_all(needle, cap=8):
        outs, s = [], 0
        while len(outs) < cap:
            i = body.find(needle, s)
            if i == -1:
                break
            outs.append(i)
            s = i + max(1, len(needle))
        return outs

    offsets = _find_all(marker)
    if not offsets and payload:
        offsets = _find_all(payload)
        if not offsets:
            # HTML-escaped fallback: the payload was entity-encoded on its way in
            esc = html_escape(payload)
            if esc != payload and esc in body:
                return ReflectionContext(
                    context=Context.HTML_ESCAPED,
                    sub_context=SubContext.NONE,
                    severity=Severity.LOW,
                    confidence=0.9,
                    marker_offset=body.find(esc),
                    evidence=Evidence(parser_used="string_search",
                                     notes=["payload_found_html_escaped"]),
                )
            return ReflectionContext()   # not found
    if not offsets:
        return ReflectionContext()

    def _classify_at(off):
        """Steps 2-6 for ONE occurrence. Returns (ReflectionContext, is_exec)."""
        # ─── 2. HTML localization ─────────────────────────────────────────────
        html_loc = analyze_html(body, off)

        ev = Evidence(
            element_tag=html_loc.element_tag,
            element_path=html_loc.element_path,
            attribute_name=html_loc.attribute_name,
            quote_char=html_loc.quote_char,
            parser_used=html_loc.parser_used,
        )
        before, after = _snippets(body, off)
        ev.snippet_before = before
        ev.snippet_after  = after
        if html_loc.notes:
            ev.notes.extend(html_loc.notes)

        ctx_obj = ReflectionContext(
            context=html_loc.context,
            sub_context=html_loc.sub_context,
            marker_offset=off,
            evidence=ev,
        )

        # ─── 3. Refine inside <script> → call JS analyzer ─────────────────────
        if html_loc.context == Context.HTML_RAWTEXT and \
           html_loc.sub_context == SubContext.TEXT_IN_RAWTEXT_SCRIPT and \
           html_loc.container_start >= 0:
            script_src = body[html_loc.container_start:html_loc.container_end]
            local_off  = off - html_loc.container_start
            js_loc = analyze_js(script_src, local_off)
            ctx_obj.context = Context.JS
            ctx_obj.sub_context = js_loc.sub_context
            ev.js_parser_used = js_loc.parser_used
            if js_loc.quote_char:
                ev.quote_char = js_loc.quote_char
            if js_loc.notes:
                ev.notes.append(js_loc.notes)

        # ─── 4. Refine inside URL attribute → call URL analyzer ───────────────
        if html_loc.context == Context.HTML_ATTR and \
           html_loc.sub_context == SubContext.ATTR_URL and \
           html_loc.container_start >= 0:
            attr_value_raw = body[html_loc.container_start:html_loc.container_end]
            # Strip enclosing quotes from container if present
            stripped_attr = attr_value_raw
            strip_start = 0
            if attr_value_raw and attr_value_raw[0] in ('"', "'"):
                strip_start = 1
                if attr_value_raw[-1] == attr_value_raw[0]:
                    stripped_attr = attr_value_raw[1:-1]
                else:
                    stripped_attr = attr_value_raw[1:]
            local_off = off - html_loc.container_start - strip_start
            url_sub = classify_url_subcontext(stripped_attr, local_off)
            # If the URL scheme is javascript: or data:, elevate to URL context —
            # but ONLY on host elements where that scheme actually navigates/fires.
            if url_sub in (SubContext.URL_JAVASCRIPT_SCHEME,
                           SubContext.URL_DATA_SCHEME):
                # v10.82 DEPTH: a javascript:/data: URL is INERT in these tags'
                # URL attributes — the browser never navigates or executes it
                # (e.g. <img src=javascript:…>, <script src=…>, <link href=…>,
                # <video/audio/source src=…>). Elevating those to CRITICAL was a
                # false positive. Demote the clearly-inert hosts; every other tag
                # (a/area/iframe/form/object/embed/base + unknown) still elevates,
                # so no real javascript:-URL XSS is lost.
                _tag = (html_loc.element_tag or "").lower()
                _INERT_JS_URL_TAGS = {
                    "img", "script", "video", "audio", "source", "track",
                    "link", "picture", "image",
                }
                if _tag in _INERT_JS_URL_TAGS:
                    ev.notes.append(f"js_url_inert_on_{_tag}")
                else:
                    ctx_obj.context = Context.URL
                    ctx_obj.sub_context = url_sub
            else:
                # Keep ATTR_URL but annotate
                ev.notes.append(f"url_sub={url_sub.value}")
                # Mid-URL-value reflection inside a QUOTED url attribute (the
                # scheme slot is already taken, e.g. href="?...&p=HERE"): the
                # only vector is a QUOTE breakout, so tell _compute_breakout to
                # require the quote char rather than ':' (which no mid-value
                # reflection can satisfy). Scheme-position reflections keep ':'.
                if html_loc.quote_char in ('"', "'") and local_off > 0:
                    ev.url_quote_breakout = True
                    ev.notes.append("url_midvalue_quote_breakout")

        # ─── 5. Compute breakout requirement + severity ───────────────────────
        ctx_obj.breakout_required = _compute_breakout(
            ctx_obj.context, ctx_obj.sub_context, ev)
        ctx_obj.severity = _compute_severity(ctx_obj.context, ctx_obj.sub_context)

        # ─── 6. Executability / sanitization gate ─────────────────────────────
        is_exec = False
        if payload and ctx_obj.context not in (Context.HTML_ESCAPED,
                                                Context.HTML_COMMENT):
            is_exec, conf, exec_notes = check_executability(
                body, off, payload, ctx_obj.breakout_required, marker=marker)
            ev.notes.extend(exec_notes)
            if not is_exec and ctx_obj.breakout_required:
                # Everything required was encoded or absent → the context is
                # effectively escaped for this specific payload. Only downgrade to
                # HTML_ESCAPED when the breakouts are literally entity-encoded.
                if any("encoded" in n for n in exec_notes):
                    ctx_obj.context = Context.HTML_ESCAPED
                    ctx_obj.sub_context = SubContext.NONE
                    ctx_obj.severity = Severity.LOW
                    ctx_obj.confidence = conf
                    ctx_obj.breakout_required = set()
                    return ctx_obj, is_exec
            # v10.19 (icanteen TP): payload je v JS stringu, ALE obsahuje
            # NEescapovaný breakout znak (quote), který string ukončí → kód za ním
            # se vykoná. To je reálný script-context XSS, ne neškodný js_string.
            if (is_exec and ctx_obj.context == Context.JS
                    and ctx_obj.sub_context in (SubContext.JS_STRING_SINGLE,
                                                SubContext.JS_STRING_DOUBLE,
                                                SubContext.JS_TEMPLATE_LITERAL)
                    and ctx_obj.breakout_required):
                _has_raw_breakout = any("raw_breakouts_present" in n
                                        for n in ev.notes)
                if _has_raw_breakout:
                    ctx_obj.sub_context = SubContext.JS_EXECUTABLE
                    ctx_obj.severity = Severity.CRITICAL
            ctx_obj.confidence = conf
        else:
            ctx_obj.confidence = 0.9 if ctx_obj.context != Context.UNKNOWN else 0.3

        return ctx_obj, is_exec

    # classify every occurrence, keep the most dangerous — executability first
    # (a raw-breakout reflection that fires beats a quote-gated JS-string one),
    # then severity as the tiebreaker.
    _results = [_classify_at(o) for o in offsets]

    def _rank(item):
        cobj, ie = item
        _sev = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
            str(getattr(cobj.severity, "value", cobj.severity)).lower(), 0)
        return (1 if ie else 0, _sev)

    return max(_results, key=_rank)[0]


# ══════════════════════════════════════════════════════════════════════════════
# LEGACY DROP-IN
# ══════════════════════════════════════════════════════════════════════════════

def classify_reflection_context_v2(body: str, payload: str,
                                    marker: Optional[str] = None) -> Optional[str]:
    """
    Drop-in replacement for xss_grenade.py's classify_reflection_context().

    Returns one of:
        "script_body" | "event_handler" | "href_attr" | "html_attr" |
        "html_escaped" | "js_string" | "html_comment" | "html_body"
        or None if no reflection found.
    """
    from context_engine import legacy_string   # type: ignore[import-not-found]

    marker = marker or payload
    ctx = analyze(body, marker, payload)
    if ctx.context == Context.UNKNOWN and ctx.marker_offset < 0:
        return None
    return legacy_string(ctx)
