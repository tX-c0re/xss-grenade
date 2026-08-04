"""
context_engine.py
=================

Precision-grade context detection for XSS reflections.

Replaces the regex-based `classify_reflection_context()` in xss_grenade.py
with a real parser stack:

    1) tree-sitter-html  → robust HTML parser (tolerates broken markup)
    2) BeautifulSoup(lxml) → fallback / cross-check + DOM walk
    3) esprima + tree-sitter-javascript → JS sub-context inside <script> blocks
    4) URL-aware sub-classification for href/src/action/formaction
    5) CSS context detection for <style> and style="" reflections

Public API
----------

analyze(body: str, marker: str, payload: Optional[str]=None) -> ReflectionContext

    Returns a rich structured object describing *where* a marker/payload
    reflection landed in the response and *what* a payload would need to
    break out of that location.

legacy_string(ctx: ReflectionContext) -> str

    Converts a ReflectionContext to the legacy string values used by the
    rest of xss_grenade.py (script_body | event_handler | href_attr |
    html_attr | html_escaped | js_string | html_comment | html_body).

classify_reflection_context_v2(body, payload, marker=None) -> Optional[str]

    Drop-in replacement for the existing classify_reflection_context().
    Under the hood it calls analyze() and maps to the legacy string,
    so existing callers (worker_task, inject_post_for_stored, …) keep
    working without change.

Design notes
------------
- The engine is offset-based: every AST node carries (start, end) byte
  offsets, so once we find the marker in the body we can locate it in
  the tree in O(log n) via iterative descent rather than re-parsing.
- We always keep `body` as **text** (str) internally and encode to bytes
  only for tree-sitter. Offsets are tracked in **characters** in the
  public API to match `body.find(marker)`.
- Parser failures never crash analyze() — each stage is guarded and
  degrades to the next-best source (tree-sitter-html → bs4 → regex).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional, Set, Tuple, Dict, Any
from html import escape as html_escape
from urllib.parse import urlparse

# ── Parser imports (all guarded) ──────────────────────────────────────────────
try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False

try:
    import esprima
    _ESPRIMA_AVAILABLE = True
except ImportError:
    _ESPRIMA_AVAILABLE = False

try:
    import tree_sitter_javascript
    import tree_sitter_html
    from tree_sitter import Language, Parser
    _TS_JS_LANG = Language(tree_sitter_javascript.language())
    _TS_HTML_LANG = Language(tree_sitter_html.language())
    _TS_AVAILABLE = True
except Exception:  # pragma: no cover
    _TS_AVAILABLE = False
    _TS_JS_LANG = None
    _TS_HTML_LANG = None

log = logging.getLogger("context_engine")


# ══════════════════════════════════════════════════════════════════════════════
# DATA MODEL
# ══════════════════════════════════════════════════════════════════════════════

class Context(str, Enum):
    """Top-level context family."""
    HTML_TEXT       = "html_text"        # between tags, e.g. <p>HERE</p>
    HTML_ATTR       = "html_attr"        # inside attribute value
    HTML_ATTR_NAME  = "html_attr_name"   # reflection as attribute name (rare, dangerous)
    HTML_COMMENT    = "html_comment"     # inside <!-- … -->
    HTML_CDATA      = "html_cdata"       # inside <![CDATA[ … ]]>
    HTML_RAWTEXT    = "html_rawtext"     # inside <script>/<style>/<textarea>/<title>
    JS              = "js"               # inside inline <script>
    CSS             = "css"              # inside <style> or style=""
    URL             = "url"              # inside href/src/action/formaction
    HTML_ESCAPED    = "html_escaped"     # reflected but breakouts were escaped
    UNKNOWN         = "unknown"


class SubContext(str, Enum):
    """Fine-grained location within the top-level context."""
    # HTML attribute flavours
    ATTR_VALUE_DOUBLE     = "attr_value_double"      # attr="…HERE…"
    ATTR_VALUE_SINGLE     = "attr_value_single"      # attr='…HERE…'
    ATTR_VALUE_UNQUOTED   = "attr_value_unquoted"    # attr=…HERE…
    ATTR_EVENT_HANDLER    = "attr_event_handler"     # onclick="HERE"
    ATTR_URL              = "attr_url"               # href/src/action/formaction
    ATTR_STYLE            = "attr_style"             # style="HERE"
    ATTR_SRCDOC           = "attr_srcdoc"            # iframe srcdoc="HERE"

    # JS flavours inside <script>
    JS_STRING_DOUBLE      = "js_string_double"
    JS_STRING_SINGLE      = "js_string_single"
    JS_TEMPLATE_LITERAL   = "js_template_literal"    # inside `…HERE…` (no ${})
    JS_TEMPLATE_EXPR      = "js_template_expr"      # inside ${HERE}
    JS_REGEX              = "js_regex"               # inside /…HERE…/
    JS_COMMENT_LINE       = "js_comment_line"        # // HERE
    JS_COMMENT_BLOCK      = "js_comment_block"       # /* HERE */
    JS_IDENTIFIER         = "js_identifier"          # bare identifier / property
    JS_PROPERTY_KEY       = "js_property_key"        # {HERE: …}
    JS_EXECUTABLE         = "js_executable"          # raw JS token position (RCE-level)

    # URL flavours (after attr_url classification)
    URL_SCHEME            = "url_scheme"             # HERE://example
    URL_HOST              = "url_host"
    URL_PATH              = "url_path"
    URL_QUERY             = "url_query"
    URL_FRAGMENT          = "url_fragment"
    URL_JAVASCRIPT_SCHEME = "url_javascript_scheme"  # href="javascript:HERE"
    URL_DATA_SCHEME       = "url_data_scheme"        # href="data:text/html,HERE"

    # HTML text flavours
    TEXT_NORMAL           = "text_normal"
    TEXT_IN_RAWTEXT_SCRIPT = "text_in_rawtext_script"   # before JS parse succeeds
    TEXT_IN_RAWTEXT_STYLE  = "text_in_rawtext_style"
    TEXT_IN_RAWTEXT_TEXTAREA = "text_in_rawtext_textarea"
    TEXT_IN_RAWTEXT_TITLE = "text_in_rawtext_title"

    # CSS flavours
    CSS_VALUE             = "css_value"
    CSS_SELECTOR          = "css_selector"
    CSS_URL               = "css_url"                # url(HERE)
    CSS_IMPORT            = "css_import"             # @import HERE

    NONE                  = "none"


class Severity(str, Enum):
    CRITICAL = "critical"   # direct JS exec or tag injection possible
    HIGH     = "high"       # quoted attr breakout possible / URL scheme
    MEDIUM   = "medium"     # text-only, tag injection hypothetical
    LOW      = "low"        # escaped / non-exploitable
    NONE     = "none"


@dataclass
class Evidence:
    """What the engine saw — kept verbose for debugging / reporting."""
    element_tag:        Optional[str] = None          # e.g. "script", "a", "div"
    element_path:       Optional[str] = None          # "html>body>div.foo>a"
    attribute_name:     Optional[str] = None          # e.g. "href"
    quote_char:         Optional[str] = None          # '"', "'", None (unquoted)
    snippet_before:     str = ""                      # ≤ 80 chars before marker
    snippet_after:      str = ""                      # ≤ 80 chars after marker
    parser_used:        str = "none"                  # "tree_sitter" | "bs4" | "regex"
    js_parser_used:     Optional[str] = None          # "esprima" | "tree_sitter" | None
    # True when the reflection sits MID-VALUE inside a QUOTED url attribute
    # (e.g. a query param reflected into href="?...&p=HERE"). There the scheme
    # slot is already taken, so the exploit is a QUOTE breakout, not scheme
    # injection — _compute_breakout requires the quote char instead of ':'.
    url_quote_breakout: bool = False
    notes:              List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, "", [])}


@dataclass
class ReflectionContext:
    """Rich structured result."""
    context:          Context         = Context.UNKNOWN
    sub_context:      SubContext      = SubContext.NONE
    severity:         Severity        = Severity.NONE
    breakout_required: Set[str]       = field(default_factory=set)
    confidence:       float           = 0.0           # 0.0 – 1.0
    marker_offset:    int             = -1
    evidence:         Evidence        = field(default_factory=Evidence)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "context":           self.context.value,
            "sub_context":       self.sub_context.value,
            "severity":          self.severity.value,
            "breakout_required": sorted(self.breakout_required),
            "confidence":        round(self.confidence, 3),
            "marker_offset":     self.marker_offset,
            "evidence":          self.evidence.to_dict(),
        }

    def __repr__(self) -> str:
        return (f"ReflectionContext({self.context.value}/{self.sub_context.value} "
                f"sev={self.severity.value} conf={self.confidence:.2f} "
                f"breakout={sorted(self.breakout_required)})")


# ══════════════════════════════════════════════════════════════════════════════
# LEGACY STRING MAPPING
# ══════════════════════════════════════════════════════════════════════════════

def legacy_string(ctx: ReflectionContext) -> str:
    """
    Map rich context → the string values expected by existing xss_grenade.py
    callers:
        script_body | event_handler | href_attr | html_attr |
        html_escaped | js_string | html_comment | html_body
    """
    if ctx.context == Context.HTML_ESCAPED:
        return "html_escaped"
    if ctx.context == Context.HTML_COMMENT:
        return "html_comment"

    if ctx.context == Context.JS:
        # JS string / template → downstream treats as FP unless quote breakout
        if ctx.sub_context in (SubContext.JS_STRING_SINGLE,
                               SubContext.JS_STRING_DOUBLE):
            return "js_string"
        if ctx.sub_context == SubContext.JS_TEMPLATE_LITERAL:
            return "js_string"
        if ctx.sub_context in (SubContext.JS_COMMENT_LINE,
                               SubContext.JS_COMMENT_BLOCK):
            return "html_comment"   # same FP treatment
        # JS_EXECUTABLE, JS_TEMPLATE_EXPR, JS_IDENTIFIER, JS_PROPERTY_KEY,
        # JS_REGEX → very dangerous, falls under script_body
        return "script_body"

    if ctx.context == Context.HTML_ATTR:
        if ctx.sub_context == SubContext.ATTR_EVENT_HANDLER:
            return "event_handler"
        if ctx.sub_context == SubContext.ATTR_URL:
            return "href_attr"
        if ctx.sub_context == SubContext.ATTR_SRCDOC:
            return "script_body"    # srcdoc is a mini-HTML document → critical
        return "html_attr"

    if ctx.context == Context.URL:
        return "href_attr"

    if ctx.context == Context.CSS:
        # CSS injection is its own beast — legacy doesn't have it, treat as html_attr
        return "html_attr"

    if ctx.context == Context.HTML_RAWTEXT:
        # Reflection inside a raw-text element without JS subcontext resolved
        # → conservatively treat as script_body for payload bank selection
        return "script_body"

    if ctx.context == Context.HTML_TEXT:
        return "html_body"

    if ctx.context == Context.HTML_ATTR_NAME:
        return "html_attr"

    return "html_body"


# ══════════════════════════════════════════════════════════════════════════════
# BREAKOUT REQUIREMENTS
# ══════════════════════════════════════════════════════════════════════════════

def _compute_breakout(ctx: Context, sub: SubContext,
                       evidence: Evidence) -> Set[str]:
    """
    Return the minimal set of characters/sequences a payload must emit RAW
    (unescaped) to escape the current context and execute code.
    """
    need: Set[str] = set()

    if ctx == Context.HTML_TEXT or ctx == Context.HTML_ATTR_NAME:
        need.update({"<"})                              # new tag
    elif ctx == Context.HTML_ATTR:
        q = evidence.quote_char
        if q == '"':
            need.update({'"'})
        elif q == "'":
            need.update({"'"})
        else:                                            # unquoted
            need.update({" ", ">"})
        # Event handler / URL attrs can execute *without* quote breakout
        if sub == SubContext.ATTR_EVENT_HANDLER:
            need = set()                                 # direct JS eval
        elif sub == SubContext.ATTR_URL:
            # A URL attribute is attacked two ways:
            #  - scheme injection at the value START (javascript:/data:) → needs ':'
            #  - quote breakout anywhere in a QUOTED value — the ONLY vector when the
            #    reflection is mid-URL (e.g. a query param inside href="?...&p=HERE"),
            #    where the scheme slot is already occupied. `url_quote_breakout` is set
            #    by the URL refinement (_engine.analyze) for exactly that case.
            if getattr(evidence, "url_quote_breakout", False) and q in ('"', "'"):
                need = {q}                               # must close the quote to inject
            else:
                need = {":"}                             # "javascript:" scheme
        elif sub == SubContext.ATTR_STYLE:
            need = {":", "(", ")"}                       # expression() / url()
    elif ctx == Context.JS:
        if sub == SubContext.JS_STRING_DOUBLE:
            need.update({'"'})
        elif sub == SubContext.JS_STRING_SINGLE:
            need.update({"'"})
        elif sub == SubContext.JS_TEMPLATE_LITERAL:
            need.update({"`", "$", "{"})
        elif sub == SubContext.JS_COMMENT_LINE:
            need.update({"\n"})
        elif sub == SubContext.JS_COMMENT_BLOCK:
            need.update({"*", "/"})
        elif sub == SubContext.JS_REGEX:
            need.update({"/"})
        elif sub in (SubContext.JS_EXECUTABLE,
                     SubContext.JS_TEMPLATE_EXPR,
                     SubContext.JS_IDENTIFIER,
                     SubContext.JS_PROPERTY_KEY):
            need = set()                                 # direct exec
    elif ctx == Context.HTML_COMMENT:
        need.update({"-", ">"})                         # "-->"
    elif ctx == Context.HTML_RAWTEXT:
        tag = (evidence.element_tag or "").lower()
        if tag == "script":
            need.update({"<", "/"})                     # "</script>"
        elif tag == "style":
            need.update({"<", "/"})                     # "</style>"
        elif tag in ("textarea", "title"):
            need.update({"<", "/"})
        else:
            need.update({"<"})
    elif ctx == Context.URL:
        need.update({":"})                              # scheme injection
    elif ctx == Context.CSS:
        if sub == SubContext.CSS_URL:
            need.update({")"})
        else:
            # v10.82 DEPTH: a <style>-BLOCK reflection (Context.CSS/CSS_VALUE) can
            # only reach JS by escaping the rawtext with </style> — it needs '<'
            # and '/'. The old {";",":"} over-claimed executability (CSS values
            # routinely echo ; and : raw while '<' is entity-encoded, yet no JS
            # runs without </style>), producing false "executable" verdicts.
            need.update({"<", "/"})                     # "</style>"

    return need


def _compute_severity(ctx: Context, sub: SubContext) -> Severity:
    if ctx == Context.HTML_ESCAPED:
        return Severity.LOW
    if ctx == Context.HTML_COMMENT:
        return Severity.LOW
    if ctx == Context.JS:
        if sub in (SubContext.JS_COMMENT_LINE, SubContext.JS_COMMENT_BLOCK):
            return Severity.LOW
        if sub in (SubContext.JS_STRING_DOUBLE, SubContext.JS_STRING_SINGLE,
                   SubContext.JS_TEMPLATE_LITERAL, SubContext.JS_REGEX):
            return Severity.HIGH   # quote breakout = full RCE
        return Severity.CRITICAL
    if ctx == Context.HTML_ATTR:
        if sub in (SubContext.ATTR_EVENT_HANDLER, SubContext.ATTR_SRCDOC):
            return Severity.CRITICAL
        if sub == SubContext.ATTR_URL:
            return Severity.HIGH
        return Severity.MEDIUM
    if ctx == Context.HTML_RAWTEXT:
        return Severity.CRITICAL    # inside <script>/<style> raw text
    if ctx == Context.HTML_TEXT:
        return Severity.MEDIUM      # new tag injection possible
    if ctx == Context.URL:
        return Severity.HIGH
    if ctx == Context.CSS:
        return Severity.MEDIUM
    return Severity.NONE


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC RE-EXPORTS (lazy, avoid circular import)
# ══════════════════════════════════════════════════════════════════════════════

def analyze(body: str, marker: str, payload: Optional[str] = None) -> "ReflectionContext":
    """Locate `marker` in `body` and return a structured ReflectionContext.
    See `_engine.analyze` for full documentation."""
    from _engine import analyze as _impl   # lazy to break circular import
    return _impl(body, marker, payload)


def classify_reflection_context_v2(body: str, payload: str,
                                    marker: Optional[str] = None) -> Optional[str]:
    """Drop-in replacement for xss_grenade.classify_reflection_context().
    Returns legacy string values (script_body, html_attr, html_escaped, …)."""
    from _engine import classify_reflection_context_v2 as _impl
    return _impl(body, payload, marker)


# ══════════════════════════════════════════════════════════════════════════════
# v2 GATE / CLASSIFIER RE-EXPORTS (added 2026-01)
# ══════════════════════════════════════════════════════════════════════════════
# These are lazy re-exports so callers can do:
#   from context_engine import gate_executability, classify_payload_static, ...

def encoded_marker_set(*args, **kwargs):
    from _render_gate import encoded_marker_set as _impl
    return _impl(*args, **kwargs)


def gate_executability(*args, **kwargs):
    from _render_gate import gate_executability as _impl
    return _impl(*args, **kwargs)


def classify_reflection_form(*args, **kwargs):
    from _render_gate import classify_reflection_form as _impl
    return _impl(*args, **kwargs)


def is_form_executable(*args, **kwargs):
    from _render_gate import is_form_executable as _impl
    return _impl(*args, **kwargs)


def classify_payload_static(*args, **kwargs):
    from _exploit_classifier import classify_payload_static as _impl
    return _impl(*args, **kwargs)


def classify_response(*args, **kwargs):
    from _exploit_classifier import classify_response as _impl
    return _impl(*args, **kwargs)


def merge_static_dynamic(*args, **kwargs):
    from _exploit_classifier import merge_static_dynamic as _impl
    return _impl(*args, **kwargs)


def classify_response_renderability(*args, **kwargs):
    from _response_aware import classify_response_renderability as _impl
    return _impl(*args, **kwargs)


def apply_downgrade(*args, **kwargs):
    from _response_aware import apply_downgrade as _impl
    return _impl(*args, **kwargs)


def is_payload_just_json_string_field(*args, **kwargs):
    from _response_aware import is_payload_just_json_string_field as _impl
    return _impl(*args, **kwargs)


__all__ = [
    "Context", "SubContext", "Severity",
    "Evidence", "ReflectionContext",
    "analyze", "classify_reflection_context_v2",
    "legacy_string",
    # v2 — render gate
    "encoded_marker_set", "gate_executability",
    "classify_reflection_form", "is_form_executable",
    # v2 — exploit classifier
    "classify_payload_static", "classify_response", "merge_static_dynamic",
    # v2 — response-aware
    "classify_response_renderability", "apply_downgrade",
    "is_payload_just_json_string_field",
]
