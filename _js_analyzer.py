"""
_js_analyzer.py
===============
JavaScript sub-context analysis inside inline <script> blocks.

Goal: when the HTML analyzer tells us the marker is inside a <script>
body, figure out *precisely* what JS construct it landed in:

    - double-quoted string literal
    - single-quoted string literal
    - template literal (backticks)
    - template literal expression (${…})
    - line comment  //…
    - block comment /*…*/
    - regex literal /…/
    - identifier / property key
    - "executable" position (raw token slot where JS will be eval'd)

Strategy:
    1) esprima.tokenize(js_source, loc=True) — fast, character-offset
       accurate, handles every ES2017+ construct we care about.
    2) tree-sitter-javascript — second opinion, used when esprima parse
       fails (malformed / truncated JS from SSR) because tree-sitter
       is error-tolerant.
    3) Regex last resort.

esprima is preferred because its token stream is trivial to map: each
token has .loc with line/column, and we convert the script-relative
char offset we got from the HTML analyzer into the same frame.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional, List, Tuple

from context_engine import (  # type: ignore[import-not-found]
    Context, SubContext, _ESPRIMA_AVAILABLE, _TS_AVAILABLE, _TS_JS_LANG,
)

if _ESPRIMA_AVAILABLE:
    import esprima
if _TS_AVAILABLE:
    from tree_sitter import Parser

log = logging.getLogger("context_engine.js")


@dataclass
class _JsLocation:
    sub_context:  SubContext = SubContext.JS_EXECUTABLE
    parser_used:  str = "none"
    notes:        str = ""
    quote_char:   Optional[str] = None   # ' / " / ` when inside a string/template


# ══════════════════════════════════════════════════════════════════════════════
# ESPRIMA PATH
# ══════════════════════════════════════════════════════════════════════════════

def _esprima_analyze(script_source: str, local_offset: int) -> Optional[_JsLocation]:
    """Return JS location for a marker at *character* `local_offset` inside
    `script_source`. Returns None if esprima can't parse."""
    if not _ESPRIMA_AVAILABLE:
        return None
    # Convert char offset → (line, column) — esprima reports 1-based lines,
    # 0-based columns.
    line = 1
    col = 0
    for i, ch in enumerate(script_source):
        if i >= local_offset:
            break
        if ch == "\n":
            line += 1
            col = 0
        else:
            col += 1

    try:
        tokens = esprima.tokenize(
            script_source,
            options={"loc": True, "comment": True, "range": True,
                     "tolerant": True},
        )
    except Exception as e:
        log.debug("esprima.tokenize failed: %s", e)
        return None

    loc = _JsLocation(parser_used="esprima")

    # esprima tokens: each .type ∈ {
    #   "Boolean", "<end>", "Identifier", "Keyword", "Null", "Numeric",
    #   "Punctuator", "String", "RegularExpression", "Template" }
    # Comments come through as separate "LineComment"/"BlockComment" items
    # when comment=True is set (actually attached to .comments on Program
    # for parse(), but tokenize() returns them inline as type "BlockComment"
    # / "LineComment").

    for tok in tokens:
        t_loc = getattr(tok, "loc", None)
        if t_loc is None:
            continue
        # t_loc.start = {"line": L, "column": C}; .end likewise
        start_line = t_loc.start.line
        start_col  = t_loc.start.column
        end_line   = t_loc.end.line
        end_col    = t_loc.end.column

        if _pos_inside(line, col, start_line, start_col, end_line, end_col):
            tt = tok.type
            val = getattr(tok, "value", "") or ""
            if tt == "String":
                if val.startswith('"'):
                    loc.sub_context = SubContext.JS_STRING_DOUBLE
                    loc.quote_char = '"'
                elif val.startswith("'"):
                    loc.sub_context = SubContext.JS_STRING_SINGLE
                    loc.quote_char = "'"
                return loc
            if tt == "Template":
                # esprima emits Template tokens for the string parts of a
                # template literal (including NoSubstitutionTemplate, head,
                # middle, tail). If marker is inside one of those token
                # spans → literal portion; otherwise the ${…} expression
                # part is parsed as regular tokens.
                loc.sub_context = SubContext.JS_TEMPLATE_LITERAL
                loc.quote_char = "`"
                return loc
            if tt == "RegularExpression":
                loc.sub_context = SubContext.JS_REGEX
                loc.quote_char = "/"
                return loc
            if tt == "LineComment" or tt == "BlockComment":
                loc.sub_context = (SubContext.JS_COMMENT_LINE if tt == "LineComment"
                                    else SubContext.JS_COMMENT_BLOCK)
                return loc
            if tt == "Identifier":
                loc.sub_context = SubContext.JS_IDENTIFIER
                return loc
            # Keyword, Punctuator, Numeric, Boolean, Null: executable
            loc.sub_context = SubContext.JS_EXECUTABLE
            return loc

    # Marker landed in whitespace / between tokens → executable slot
    # (whitespace between statements is a valid injection point)
    loc.sub_context = SubContext.JS_EXECUTABLE
    return loc


def _pos_inside(L: int, C: int,
                sL: int, sC: int, eL: int, eC: int) -> bool:
    """Is (L, C) inside [(sL, sC), (eL, eC))?"""
    if L < sL or L > eL:
        return False
    if L == sL and C < sC:
        return False
    if L == eL and C >= eC:
        return False
    return True


# ══════════════════════════════════════════════════════════════════════════════
# TREE-SITTER PATH
# ══════════════════════════════════════════════════════════════════════════════

# Map tree-sitter-javascript node types to our SubContext.
# Note: tree-sitter-javascript uses node types like "string", "template_string",
# "template_substitution", "regex", "comment", "identifier",
# "property_identifier", "string_fragment", "escape_sequence", …
_TS_NODE_MAP = {
    "string":                None,          # needs quote-char refinement
    "string_fragment":        None,
    "template_string":        SubContext.JS_TEMPLATE_LITERAL,
    "template_substitution":  SubContext.JS_TEMPLATE_EXPR,
    "regex":                  SubContext.JS_REGEX,
    "regex_pattern":          SubContext.JS_REGEX,
    "comment":                None,          # needs // vs /* refinement
    "identifier":             SubContext.JS_IDENTIFIER,
    "property_identifier":    SubContext.JS_PROPERTY_KEY,
    "shorthand_property_identifier": SubContext.JS_PROPERTY_KEY,
}


def _ts_js_analyze(script_source: str, local_offset: int) -> Optional[_JsLocation]:
    if not _TS_AVAILABLE or _TS_JS_LANG is None:
        return None
    try:
        parser = Parser(_TS_JS_LANG)
        src_bytes = script_source.encode("utf-8", errors="replace")
        tree = parser.parse(src_bytes)
    except Exception as e:
        log.debug("tree-sitter-js parse failed: %s", e)
        return None

    # Convert char offset to byte offset
    try:
        target_byte = len(script_source[:local_offset].encode("utf-8"))
    except Exception:
        target_byte = local_offset

    # Walk down
    node = tree.root_node
    path = [node]
    while True:
        next_child = None
        for child in node.children:
            if child.start_byte <= target_byte < child.end_byte:
                next_child = child
                break
        if next_child is None:
            break
        path.append(next_child)
        node = next_child

    loc = _JsLocation(parser_used="tree_sitter")

    # Walk from deepest up; first interesting node wins.
    for n in reversed(path):
        mapped = _TS_NODE_MAP.get(n.type)
        if mapped is not None:
            loc.sub_context = mapped
            return loc
        if n.type == "string" or n.type == "string_fragment":
            # Inspect first byte of the enclosing "string" to get quote.
            # If n is string_fragment, find parent string.
            s_node = n if n.type == "string" else n.parent
            if s_node is not None and s_node.start_byte < s_node.end_byte:
                first = src_bytes[s_node.start_byte:s_node.start_byte + 1].decode(
                    "utf-8", errors="replace")
                if first == '"':
                    loc.sub_context = SubContext.JS_STRING_DOUBLE
                    loc.quote_char = '"'
                elif first == "'":
                    loc.sub_context = SubContext.JS_STRING_SINGLE
                    loc.quote_char = "'"
                else:
                    loc.sub_context = SubContext.JS_STRING_DOUBLE
            return loc
        if n.type == "comment":
            txt = src_bytes[n.start_byte:n.end_byte].decode(
                "utf-8", errors="replace")
            if txt.startswith("//"):
                loc.sub_context = SubContext.JS_COMMENT_LINE
            else:
                loc.sub_context = SubContext.JS_COMMENT_BLOCK
            return loc

    loc.sub_context = SubContext.JS_EXECUTABLE
    return loc


# ══════════════════════════════════════════════════════════════════════════════
# REGEX FALLBACK
# ══════════════════════════════════════════════════════════════════════════════

_RE_LINE_COMMENT  = re.compile(r"//[^\n]*", re.M)
_RE_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def _regex_js_fallback(script_source: str, local_offset: int) -> _JsLocation:
    loc = _JsLocation(parser_used="regex")
    # Block comment?
    for m in _RE_BLOCK_COMMENT.finditer(script_source):
        if m.start() <= local_offset < m.end():
            loc.sub_context = SubContext.JS_COMMENT_BLOCK
            return loc
    # Line comment?
    for m in _RE_LINE_COMMENT.finditer(script_source):
        if m.start() <= local_offset < m.end():
            loc.sub_context = SubContext.JS_COMMENT_LINE
            return loc
    # Inside a quoted string? Count unescaped quotes before offset.
    prefix = script_source[:local_offset]
    # Strip comments from prefix first (crude)
    prefix_clean = _RE_BLOCK_COMMENT.sub(" ", prefix)
    prefix_clean = _RE_LINE_COMMENT.sub(" ", prefix_clean)
    # Unescaped quote counting
    def _count_unescaped(s: str, q: str) -> int:
        n = 0
        i = 0
        while i < len(s):
            if s[i] == "\\":
                i += 2
                continue
            if s[i] == q:
                n += 1
            i += 1
        return n
    dq = _count_unescaped(prefix_clean, '"')
    sq = _count_unescaped(prefix_clean, "'")
    bq = _count_unescaped(prefix_clean, "`")
    if dq % 2 == 1:
        loc.sub_context = SubContext.JS_STRING_DOUBLE
        loc.quote_char = '"'
        return loc
    if sq % 2 == 1:
        loc.sub_context = SubContext.JS_STRING_SINGLE
        loc.quote_char = "'"
        return loc
    if bq % 2 == 1:
        loc.sub_context = SubContext.JS_TEMPLATE_LITERAL
        loc.quote_char = "`"
        return loc
    loc.sub_context = SubContext.JS_EXECUTABLE
    return loc


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY
# ══════════════════════════════════════════════════════════════════════════════

def analyze_js(script_source: str, local_offset: int) -> _JsLocation:
    """Esprima → tree-sitter → regex chain."""
    # Esprima first — most accurate on well-formed code
    loc = _esprima_analyze(script_source, local_offset)
    if loc is not None and loc.sub_context != SubContext.JS_EXECUTABLE:
        # If esprima confidently placed us in string/comment/etc we're done
        return loc
    # Otherwise try tree-sitter (tolerates broken JS)
    ts_loc = _ts_js_analyze(script_source, local_offset)
    if ts_loc is not None:
        # Prefer ts if it says something more specific than "executable"
        if ts_loc.sub_context != SubContext.JS_EXECUTABLE:
            return ts_loc
        if loc is not None:
            return loc
        return ts_loc
    if loc is not None:
        return loc
    return _regex_js_fallback(script_source, local_offset)
