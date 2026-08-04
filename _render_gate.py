"""
_render_gate.py
===============
Re-render / encoding gate for XSS reflection verification.

Problem this solves
-------------------
Many false positives in XSS scanners come from "decoded reflection"
where the server reflects an encoded marker back as text in its decoded
form, but the encoded form NEVER decodes in the browser DOM. Examples
from real-world report (example.com):

    payload sent     →  reflected as  →  exploitable?
    \u003c          →  \u003c        →  NO (literal text)
    %253C           →  %253C or %3C  →  NO (literal text)
    \x3c            →  \x3c          →  NO (literal text)
    </body>         →  </body>       →  MAYBE (tag injection, see _exploit_classifier)
    raw <           →  raw <         →  YES (true XSS primitive)

The gate sends the marker in MULTIPLE encoding forms simultaneously and
checks which forms survive to the response in a way that the BROWSER
will decode/execute. Only payloads whose breakout characters survive in
"executable form" pass the gate.

Public API
----------

    encoded_marker_set(base_marker: str) -> List[EncodedMarker]
        Build the encoding canary set for a given base marker.

    classify_reflection_form(body: str, marker: EncodedMarker)
                                            -> ReflectionForm
        Determine HOW a marker variant survived in the response body.

    gate_executability(body: str, base_marker: str,
                        breakout_chars: Set[str]) -> GateVerdict
        Top-level: did the breakout chars survive in EXECUTABLE form?

Integration
-----------
The scanner does ONE additional probe per finding: it sends a
multi-encoded marker to the same parameter, gets the response, and
runs gate_executability(). If verdict.executable == False, the finding
is downgraded or rejected before reaching on_hit().

This adds 1 extra HTTP request per *candidate* finding (not per probe),
which in practice means ~0-3 extra requests per scanned parameter.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Set, Optional, Dict, Tuple

log = logging.getLogger("context_engine.render_gate")


# ══════════════════════════════════════════════════════════════════════════════
# DATA MODEL
# ══════════════════════════════════════════════════════════════════════════════

class ReflectionForm(str, Enum):
    """How a marker variant appears in the response body."""
    RAW            = "raw"             # exact payload byte-for-byte → executable
    HTML_ENTITY    = "html_entity"     # &lt; etc. → NOT executable as char
    JS_UNICODE     = "js_unicode"      # \u003c → NOT executable in HTML, only in JS strings
    JS_HEX         = "js_hex"          # \x3c → same
    URL_ENCODED    = "url_encoded"     # %3C → NOT executable
    DOUBLE_ENCODED = "double_encoded"  # %253C, &amp;lt; → NOT executable
    NUMERIC_ENTITY = "numeric_entity"  # &#60; / &#x3c; → entity, decoded by browser to char
                                        #   IS executable in HTML text context
                                        #   NOT executable in attribute (browser doesn't
                                        #   re-parse attribute values)
    NOT_FOUND      = "not_found"       # this variant didn't reflect at all


@dataclass
class EncodedMarker:
    """One encoding variant of a base marker, ready to be sent."""
    form:        ReflectionForm
    payload:     str           # what we send (URL-encoded for transport)
    body_form:   str           # what we expect to see in body if reflected raw
    description: str = ""

    def __repr__(self) -> str:
        return f"<{self.form.value}: send={self.payload!r}>"


@dataclass
class GateVerdict:
    """Result of executability gate."""
    executable:    bool
    confidence:    float                    # 0.0 – 1.0
    forms_seen:    Dict[str, ReflectionForm] = field(default_factory=dict)
    reason:        str = ""
    notes:         List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return (f"GateVerdict(exec={self.executable}, conf={self.confidence:.2f}, "
                f"reason={self.reason!r})")


# ══════════════════════════════════════════════════════════════════════════════
# ENCODING VARIANTS BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def encoded_marker_set(base_marker: str) -> List[EncodedMarker]:
    """
    Build a deterministic set of encoded variants for a base marker.

    The base marker should be unique, alphanumeric, and contain a known
    "breakout sentinel character" we can encode. Convention:
        base_marker = "<" + tail   (e.g. "<XSSGRENADE7K3")

    The leading "<" is the breakout sentinel — we test how it survives.
    Tail is alphanumeric for easy grep.

    Returns ~7 variants. Each has:
        - payload: what to send (the "<" replaced by encoding)
        - body_form: literal string we expect IF reflected unchanged
    """
    if not base_marker or "<" not in base_marker:
        # Caller didn't follow convention — synthesize one
        base_marker = "<" + base_marker

    sentinel = "<"
    tail = base_marker[1:]   # everything after the sentinel

    variants = [
        EncodedMarker(
            form=ReflectionForm.RAW,
            payload=f"<{tail}",
            body_form=f"<{tail}",
            description="raw <",
        ),
        EncodedMarker(
            form=ReflectionForm.HTML_ENTITY,
            payload=f"&lt;{tail}",
            body_form=f"&lt;{tail}",
            description="HTML entity &lt;",
        ),
        EncodedMarker(
            form=ReflectionForm.NUMERIC_ENTITY,
            payload=f"&#60;{tail}",
            body_form=f"&#60;{tail}",
            description="numeric entity &#60;",
        ),
        EncodedMarker(
            form=ReflectionForm.JS_UNICODE,
            payload=f"\\u003c{tail}",
            body_form=f"\\u003c{tail}",
            description="JS unicode \\u003c",
        ),
        EncodedMarker(
            form=ReflectionForm.JS_HEX,
            payload=f"\\x3c{tail}",
            body_form=f"\\x3c{tail}",
            description="JS hex \\x3c",
        ),
        EncodedMarker(
            form=ReflectionForm.URL_ENCODED,
            payload=f"%3C{tail}",        # raw, not double-URL-encoded
            body_form=f"%3C{tail}",      # if server reflects %3C as text
            description="URL-encoded %3C",
        ),
        EncodedMarker(
            form=ReflectionForm.DOUBLE_ENCODED,
            payload=f"%253C{tail}",
            body_form=f"%253C{tail}",
            description="double-encoded %253C",
        ),
    ]
    return variants


# ══════════════════════════════════════════════════════════════════════════════
# CLASSIFICATION
# ══════════════════════════════════════════════════════════════════════════════

# Pre-compiled patterns for fast detection
_RE_NUMERIC_DEC = re.compile(r"&#(\d+);")
_RE_NUMERIC_HEX = re.compile(r"&#x([0-9a-fA-F]+);")


def classify_reflection_form(body: str,
                              variant: EncodedMarker) -> ReflectionForm:
    """
    For a given variant we sent, determine HOW it appears in the body.

    Returns ReflectionForm — the actual form the variant survived AS,
    OR NOT_FOUND if no reflection at all.

    Note: a variant can be "found" but in a different form than we sent
    it (server normalizes). Example:
        we send  &lt;TAIL  (HTML entity)
        server stores in DB, retrieves, decodes to "<", echoes
        body has  <TAIL  → variant reflected as RAW (decoded once)
    """
    # 1. Did the variant arrive verbatim?
    if variant.body_form in body:
        return variant.form

    # 2. Did the SERVER decode and re-emit a different form?
    #    Look for the tail character with possible different prefix.
    tail = variant.body_form.split(variant.body_form[0], 1)[1] \
        if variant.body_form else ""
    # Actually use the variant.payload tail
    tail = variant.payload
    # Strip the encoded "<" prefix to get tail
    for prefix in ("<", "&lt;", "&#60;", "&#x3c;", "&#x3C;",
                    "\\u003c", "\\u003C", "\\x3c", "\\x3C",
                    "%3C", "%3c", "%253C", "%253c"):
        if tail.startswith(prefix):
            tail = tail[len(prefix):]
            break

    if not tail:
        return ReflectionForm.NOT_FOUND

    # 3. Tail-based search: find the tail in body, check what's before it
    idx = body.find(tail)
    if idx == -1:
        return ReflectionForm.NOT_FOUND

    # What's the 8 chars BEFORE the tail in body?
    prefix_window = body[max(0, idx - 8):idx]

    if prefix_window.endswith("<"):
        return ReflectionForm.RAW
    if prefix_window.endswith("&lt;") or prefix_window.endswith("&LT;"):
        return ReflectionForm.HTML_ENTITY
    # Numeric entities
    m = _RE_NUMERIC_DEC.search(prefix_window)
    if m and m.group(1) == "60":
        return ReflectionForm.NUMERIC_ENTITY
    m = _RE_NUMERIC_HEX.search(prefix_window)
    if m and m.group(1).lower() == "3c":
        return ReflectionForm.NUMERIC_ENTITY
    if prefix_window.endswith("\\u003c") or prefix_window.endswith("\\u003C"):
        return ReflectionForm.JS_UNICODE
    if prefix_window.endswith("\\x3c") or prefix_window.endswith("\\x3C"):
        return ReflectionForm.JS_HEX
    if prefix_window.endswith("%3C") or prefix_window.endswith("%3c"):
        return ReflectionForm.URL_ENCODED
    if prefix_window.endswith("%253C") or prefix_window.endswith("%253c"):
        return ReflectionForm.DOUBLE_ENCODED
    if prefix_window.endswith("&amp;lt;"):
        return ReflectionForm.DOUBLE_ENCODED

    # Tail found but no recognizable prefix — treat as "found in unknown form"
    # → conservative: not executable
    return ReflectionForm.NOT_FOUND


# ══════════════════════════════════════════════════════════════════════════════
# EXECUTABILITY CLASSIFICATION PER FORM
# ══════════════════════════════════════════════════════════════════════════════

# What forms are EXECUTABLE in which top-level context?
# True  = browser will interpret it as a special character / tag boundary
# False = browser shows it as plain text
_EXEC_TABLE: Dict[Tuple[str, ReflectionForm], bool] = {
    # HTML text / element body context
    ("html_text", ReflectionForm.RAW):            True,
    ("html_text", ReflectionForm.NUMERIC_ENTITY): True,   # browser decodes &#60;
    ("html_text", ReflectionForm.HTML_ENTITY):    False,  # &lt; is text in 2026
    ("html_text", ReflectionForm.JS_UNICODE):     False,  # \u003c is plain text in HTML
    ("html_text", ReflectionForm.JS_HEX):         False,
    ("html_text", ReflectionForm.URL_ENCODED):    False,
    ("html_text", ReflectionForm.DOUBLE_ENCODED): False,

    # HTML attribute value (browser does NOT re-parse attribute values)
    ("html_attr", ReflectionForm.RAW):            True,
    ("html_attr", ReflectionForm.NUMERIC_ENTITY): True,   # &quot; etc decoded in attr
    ("html_attr", ReflectionForm.HTML_ENTITY):    False,
    ("html_attr", ReflectionForm.JS_UNICODE):     False,
    ("html_attr", ReflectionForm.JS_HEX):         False,
    ("html_attr", ReflectionForm.URL_ENCODED):    False,
    ("html_attr", ReflectionForm.DOUBLE_ENCODED): False,

    # JS string literal context — \u003c IS valid escape for "<"
    ("js_string", ReflectionForm.RAW):            True,
    ("js_string", ReflectionForm.JS_UNICODE):     True,   # JS engine decodes
    ("js_string", ReflectionForm.JS_HEX):         True,
    ("js_string", ReflectionForm.HTML_ENTITY):    False,  # entities don't apply in JS
    ("js_string", ReflectionForm.NUMERIC_ENTITY): False,
    ("js_string", ReflectionForm.URL_ENCODED):    False,
    ("js_string", ReflectionForm.DOUBLE_ENCODED): False,

    # JS executable position (raw token slot)
    ("js_executable", ReflectionForm.RAW):            True,
    ("js_executable", ReflectionForm.JS_UNICODE):     True,   # \u003c parses to "<"
    ("js_executable", ReflectionForm.JS_HEX):         False,  # \x3c only valid in strings
    ("js_executable", ReflectionForm.HTML_ENTITY):    False,
    ("js_executable", ReflectionForm.NUMERIC_ENTITY): False,
    ("js_executable", ReflectionForm.URL_ENCODED):    False,
    ("js_executable", ReflectionForm.DOUBLE_ENCODED): False,

    # URL attribute (href, src) — % IS the URL encoding, browser decodes it
    ("url_attr", ReflectionForm.RAW):            True,
    ("url_attr", ReflectionForm.URL_ENCODED):    True,    # browser decodes %3C in href
    ("url_attr", ReflectionForm.NUMERIC_ENTITY): True,    # entity decoded in attr
    ("url_attr", ReflectionForm.HTML_ENTITY):    False,
    ("url_attr", ReflectionForm.JS_UNICODE):     False,
    ("url_attr", ReflectionForm.JS_HEX):         False,
    ("url_attr", ReflectionForm.DOUBLE_ENCODED): False,
}


def is_form_executable(top_context: str, form: ReflectionForm) -> bool:
    """
    Given a top-level context string ('html_text', 'html_attr', 'js_string',
    'js_executable', 'url_attr') and the form a marker survived as, return
    whether the marker is a true breakout primitive.

    If the table doesn't have an entry, return False (conservative).
    """
    return _EXEC_TABLE.get((top_context, form), False)


# ══════════════════════════════════════════════════════════════════════════════
# TOP-LEVEL GATE
# ══════════════════════════════════════════════════════════════════════════════

def gate_executability(body: str,
                        variants_sent: List[EncodedMarker],
                        top_context: str = "html_text") -> GateVerdict:
    """
    Did at least ONE encoded variant survive in EXECUTABLE form?

    Args:
        body:           the response body for the multi-encoded probe request
        variants_sent:  list of EncodedMarker we sent (typically all 7 from
                        encoded_marker_set())
        top_context:    'html_text' | 'html_attr' | 'js_string' |
                        'js_executable' | 'url_attr' — passed in by caller
                        based on context_engine output

    Returns:
        GateVerdict
    """
    forms_seen: Dict[str, ReflectionForm] = {}
    executable_forms = []

    for v in variants_sent:
        seen_form = classify_reflection_form(body, v)
        forms_seen[v.form.value] = seen_form
        if seen_form == ReflectionForm.NOT_FOUND:
            continue
        if is_form_executable(top_context, seen_form):
            executable_forms.append(v.form.value)

    if executable_forms:
        return GateVerdict(
            executable=True,
            confidence=min(1.0, 0.5 + 0.25 * len(executable_forms)),
            forms_seen=forms_seen,
            reason=f"executable_forms={executable_forms}",
            notes=[f"context={top_context}",
                   f"variants_executable={len(executable_forms)}/{len(variants_sent)}"],
        )

    # Anything reflected at all?
    found_any = [v for v, f in forms_seen.items() if f != ReflectionForm.NOT_FOUND]
    if not found_any:
        return GateVerdict(
            executable=False,
            confidence=1.0,
            forms_seen=forms_seen,
            reason="no_variant_reflected",
            notes=[f"context={top_context}"],
        )

    # Reflected, but only in non-executable forms (entities, JS escapes in HTML, …)
    return GateVerdict(
        executable=False,
        confidence=0.95,
        forms_seen=forms_seen,
        reason=f"only_inert_forms={found_any}",
        notes=[
            f"context={top_context}",
            "server reflects markers but browser will not decode them as HTML/JS primitives",
        ],
    )
