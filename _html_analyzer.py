"""
_html_analyzer.py
=================
HTML-side analysis for the context engine.

Two strategies, tried in order:

    1) tree-sitter-html  → robust, tolerates broken markup. Gives us
       character-offset-accurate AST nodes.
    2) BeautifulSoup(lxml) → fallback, used for semantic element-path
       naming and as a sanity check on tag detection.
    3) Regex last-resort → only if both parsers fail or give nothing.

The HTML analyzer returns a `_HtmlLocation` describing where the marker
landed *in the HTML dimension*. If the location is inside a <script> block,
the caller (analyze()) hands the script body off to the JS analyzer for
refinement.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Any

from context_engine import (  # type: ignore[import-not-found]
    Context, SubContext, Evidence,
    _TS_AVAILABLE, _TS_HTML_LANG, _BS4_AVAILABLE,
)

if _TS_AVAILABLE:
    from tree_sitter import Parser
if _BS4_AVAILABLE:
    from bs4 import BeautifulSoup

log = logging.getLogger("context_engine.html")


# Elements whose content is raw text (not parsed as HTML):
# <script>, <style> → own languages
# <textarea>, <title> → literal text (no entities decoded by browser as tags)
_RAWTEXT_ELEMENTS = {"script", "style", "textarea", "title", "noscript",
                      "noframes", "xmp", "iframe", "plaintext"}

# URL-bearing attributes — reflection here → ATTR_URL sub-context
_URL_ATTRS = {
    "href", "src", "action", "formaction", "data", "poster",
    "manifest", "cite", "background", "longdesc", "usemap",
    "xlink:href", "ping", "srcset",
}

# Event handler attributes start with "on"; explicit whitelist avoids "ontop"
_EVENT_ATTR_PREFIX = "on"

# Mini-HTML attributes (srcdoc is a whole nested document)
_HTML_DOC_ATTRS = {"srcdoc"}


@dataclass
class _HtmlLocation:
    """Result of the HTML-side localization pass."""
    context:        Context        = Context.UNKNOWN
    sub_context:    SubContext     = SubContext.NONE
    element_tag:    Optional[str]  = None
    element_path:   Optional[str]  = None
    attribute_name: Optional[str]  = None
    quote_char:     Optional[str]  = None
    # For JS/CSS/URL/RAWTEXT contexts — offsets of the enclosing container
    # (e.g. the <script> body) in the original body so caller can slice.
    container_start: int           = -1
    container_end:   int           = -1
    parser_used:     str           = "none"
    notes:           List[str]     = field(default_factory=list)


# ══════════════════════════════════════════════════════════════════════════════
# TREE-SITTER PATH
# ══════════════════════════════════════════════════════════════════════════════

def _ts_find_path_to_offset(root, target_byte: int) -> List[Any]:
    """Walk the tree-sitter tree to the deepest node containing target_byte.
    Returns list of nodes from root down to the leaf (inclusive)."""
    path = [root]
    node = root
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
    return path


def _char_to_byte_offset(body: str, char_offset: int) -> int:
    """Convert character offset → UTF-8 byte offset (tree-sitter operates on bytes)."""
    return len(body[:char_offset].encode("utf-8"))


def _ts_analyze_html(body: str, marker_offset: int) -> Optional[_HtmlLocation]:
    if not _TS_AVAILABLE or _TS_HTML_LANG is None:
        return None
    try:
        parser = Parser(_TS_HTML_LANG)
        body_bytes = body.encode("utf-8", errors="replace")
        tree = parser.parse(body_bytes)
    except Exception as e:
        log.debug("tree-sitter-html parse failed: %s", e)
        return None

    target_byte = _char_to_byte_offset(body, marker_offset)
    path = _ts_find_path_to_offset(tree.root_node, target_byte)
    if not path:
        return None

    loc = _HtmlLocation(parser_used="tree_sitter")

    # Walk the path from deepest upwards and figure out where we are.
    # tree-sitter-html node types we care about:
    #   "element", "script_element", "style_element",
    #   "start_tag", "end_tag", "self_closing_tag",
    #   "tag_name", "attribute", "attribute_name",
    #   "attribute_value", "quoted_attribute_value",
    #   "text", "comment",
    #   "raw_text" (body of script/style)

    leaf = path[-1]
    leaf_type = leaf.type

    # Build element_path by scanning upward for element nodes
    element_chain: List[str] = []
    enclosing_element = None
    for node in reversed(path):
        if node.type in ("element", "script_element", "style_element"):
            if enclosing_element is None:
                enclosing_element = node
            # First child of element is usually a start_tag → get tag_name
            for child in node.children:
                if child.type in ("start_tag", "self_closing_tag"):
                    for sub in child.children:
                        if sub.type == "tag_name":
                            element_chain.append(
                                body_bytes[sub.start_byte:sub.end_byte]
                                .decode("utf-8", errors="replace").lower()
                            )
                            break
                    break
    element_chain.reverse()
    if element_chain:
        loc.element_path = ">".join(element_chain)
        loc.element_tag = element_chain[-1]

    # ─── Comment ───
    # v10.19 (icanteen TP): a comment node INSIDE a <script>/<style>/rawtext
    # element is JS/CSS-irrelevant (legacy <script><!-- --></script> wrapper);
    # the code still executes. Only treat as html_comment when NOT inside such
    # a rawtext container, so we don't mislabel real script-context XSS.
    _ancestor_tag = (loc.element_tag or "").lower()
    for node in reversed(path):
        if node.type == "comment":
            if _ancestor_tag in _RAWTEXT_ELEMENTS:
                break  # inside <script>/<style>/… → not an HTML comment FP
            loc.context = Context.HTML_COMMENT
            loc.sub_context = SubContext.NONE
            loc.container_start = _byte_to_char_offset(body_bytes, node.start_byte)
            loc.container_end = _byte_to_char_offset(body_bytes, node.end_byte)
            return loc

    # ─── Inside attribute ───
    # Find the nearest "attribute" ancestor
    attr_node = None
    for node in reversed(path):
        if node.type == "attribute":
            attr_node = node
            break

    if attr_node is not None:
        # Extract attribute name
        attr_name = None
        value_node = None
        quote_char: Optional[str] = None
        for child in attr_node.children:
            if child.type == "attribute_name":
                attr_name = body_bytes[child.start_byte:child.end_byte].decode(
                    "utf-8", errors="replace").lower()
            elif child.type == "quoted_attribute_value":
                value_node = child
                # Determine quote: the first byte is either " or '
                first = body_bytes[child.start_byte:child.start_byte + 1].decode(
                    "utf-8", errors="replace")
                if first in ('"', "'"):
                    quote_char = first
            elif child.type == "attribute_value":
                value_node = child     # unquoted
                quote_char = None

        loc.attribute_name = attr_name
        loc.quote_char = quote_char

        # Is marker actually inside the value?
        if value_node is not None and \
                value_node.start_byte <= target_byte < value_node.end_byte:
            loc.context = Context.HTML_ATTR
            loc.container_start = _byte_to_char_offset(body_bytes, value_node.start_byte)
            loc.container_end = _byte_to_char_offset(body_bytes, value_node.end_byte)
            loc.sub_context = _classify_attr_subcontext(
                attr_name, quote_char, element_chain[-1] if element_chain else None)
        else:
            # Marker is in the attribute name itself → rare but dangerous
            loc.context = Context.HTML_ATTR_NAME
            loc.sub_context = SubContext.NONE
        return loc

    # ─── Raw text (inside <script>, <style>, <textarea>, <title>) ───
    for node in reversed(path):
        if node.type == "raw_text":
            loc.container_start = _byte_to_char_offset(body_bytes, node.start_byte)
            loc.container_end = _byte_to_char_offset(body_bytes, node.end_byte)
            parent_tag = (loc.element_tag or "").lower()
            if parent_tag == "script":
                loc.context = Context.HTML_RAWTEXT     # will refine to JS in caller
                loc.sub_context = SubContext.TEXT_IN_RAWTEXT_SCRIPT
            elif parent_tag == "style":
                loc.context = Context.CSS
                loc.sub_context = SubContext.CSS_VALUE
            elif parent_tag == "textarea":
                loc.context = Context.HTML_RAWTEXT
                loc.sub_context = SubContext.TEXT_IN_RAWTEXT_TEXTAREA
            elif parent_tag == "title":
                loc.context = Context.HTML_RAWTEXT
                loc.sub_context = SubContext.TEXT_IN_RAWTEXT_TITLE
            else:
                loc.context = Context.HTML_RAWTEXT
                loc.sub_context = SubContext.TEXT_NORMAL
            return loc

    # ─── Plain text between tags ───
    if leaf_type == "text":
        # BUT: if parent element is a rawtext element (textarea, title,
        # style, script, noscript, …) tree-sitter-html doesn't always
        # emit a "raw_text" node — sometimes it's just "text". Promote
        # to rawtext based on parent tag.
        parent_tag = (loc.element_tag or "").lower()
        if parent_tag in _RAWTEXT_ELEMENTS:
            # Container = text node itself (start..end covers the content)
            loc.container_start = _byte_to_char_offset(body_bytes, leaf.start_byte)
            loc.container_end = _byte_to_char_offset(body_bytes, leaf.end_byte)
            if parent_tag == "script":
                loc.context = Context.HTML_RAWTEXT
                loc.sub_context = SubContext.TEXT_IN_RAWTEXT_SCRIPT
            elif parent_tag == "style":
                loc.context = Context.CSS
                loc.sub_context = SubContext.CSS_VALUE
            elif parent_tag == "textarea":
                loc.context = Context.HTML_RAWTEXT
                loc.sub_context = SubContext.TEXT_IN_RAWTEXT_TEXTAREA
            elif parent_tag == "title":
                loc.context = Context.HTML_RAWTEXT
                loc.sub_context = SubContext.TEXT_IN_RAWTEXT_TITLE
            else:
                loc.context = Context.HTML_RAWTEXT
                loc.sub_context = SubContext.TEXT_NORMAL
            return loc
        loc.context = Context.HTML_TEXT
        loc.sub_context = SubContext.TEXT_NORMAL
        return loc

    # ─── Fallback: somewhere in the tree we can't categorise ───
    # Walk up and look for hints
    for node in reversed(path):
        if node.type in ("text",):
            loc.context = Context.HTML_TEXT
            loc.sub_context = SubContext.TEXT_NORMAL
            return loc

    loc.context = Context.HTML_TEXT
    loc.sub_context = SubContext.TEXT_NORMAL
    loc.notes.append(f"ts_leaf_type={leaf_type}")
    return loc


def _byte_to_char_offset(body_bytes: bytes, byte_off: int) -> int:
    """Convert UTF-8 byte offset → character offset."""
    try:
        return len(body_bytes[:byte_off].decode("utf-8", errors="replace"))
    except Exception:
        return byte_off   # degrade: assume ASCII


def _classify_attr_subcontext(attr_name: Optional[str],
                               quote_char: Optional[str],
                               element_tag: Optional[str]) -> SubContext:
    """Given attribute name + quote, return the fine-grained sub-context."""
    name = (attr_name or "").lower()

    if name.startswith(_EVENT_ATTR_PREFIX) and len(name) > 2:
        # on* event handler
        return SubContext.ATTR_EVENT_HANDLER

    if name in _HTML_DOC_ATTRS:
        return SubContext.ATTR_SRCDOC

    if name in _URL_ATTRS:
        return SubContext.ATTR_URL

    if name == "style":
        return SubContext.ATTR_STYLE

    # Plain attribute — distinguish by quote
    if quote_char == '"':
        return SubContext.ATTR_VALUE_DOUBLE
    elif quote_char == "'":
        return SubContext.ATTR_VALUE_SINGLE
    else:
        return SubContext.ATTR_VALUE_UNQUOTED


# ══════════════════════════════════════════════════════════════════════════════
# BEAUTIFULSOUP PATH (semantic path names + fallback)
# ══════════════════════════════════════════════════════════════════════════════

def _bs4_enrich_path(body: str, marker_offset: int,
                      loc: _HtmlLocation) -> None:
    """Add CSS-style element path to loc.element_path using BeautifulSoup."""
    if not _BS4_AVAILABLE or not loc.element_tag:
        return
    try:
        soup = BeautifulSoup(body, "lxml")
    except Exception:
        try:
            soup = BeautifulSoup(body, "html.parser")
        except Exception:
            return

    # Find the tag containing marker_offset — bs4 doesn't track offsets so
    # we scan by re-rendering and finding the marker substring position.
    # This is best-effort — tree-sitter is authoritative for offsets.
    #
    # Instead we produce a *plausible* ancestor chain from the first element
    # with the matching tag name we encounter.
    try:
        found = None
        target_tag = loc.element_tag.lower()
        for el in soup.find_all(target_tag):
            s = str(el)
            if loc.container_start != -1 and loc.container_start != 0:
                # Heuristic: prefer the first match — accurate enough for
                # reporting, not used for decisions.
                found = el
                break
            found = el
            break
        if found is not None:
            chain = []
            node = found
            while node is not None and getattr(node, "name", None):
                seg = node.name
                _id = node.get("id") if hasattr(node, "get") else None
                _cls = node.get("class") if hasattr(node, "get") else None
                if _id:
                    seg += f"#{_id}"
                elif _cls:
                    seg += f".{'.'.join(_cls)}"
                chain.append(seg)
                node = node.parent
            chain.reverse()
            if chain:
                loc.element_path = ">".join(chain)
    except Exception as e:
        log.debug("bs4 enrich failed: %s", e)


# ══════════════════════════════════════════════════════════════════════════════
# REGEX LAST-RESORT FALLBACK
# ══════════════════════════════════════════════════════════════════════════════

import re

_RE_SCRIPT_OPEN  = re.compile(r"<script\b[^>]*>", re.I)
_RE_SCRIPT_CLOSE = re.compile(r"</script\s*>", re.I)
_RE_STYLE_OPEN   = re.compile(r"<style\b[^>]*>", re.I)
_RE_STYLE_CLOSE  = re.compile(r"</style\s*>", re.I)
_RE_COMMENT      = re.compile(r"<!--.*?-->", re.S)
_RE_ATTR_NEAR    = re.compile(
    r'(?P<name>[a-zA-Z_:][\w:.\-]*)\s*=\s*(?P<q>["\']?)', re.I)


def _regex_fallback(body: str, marker_offset: int) -> _HtmlLocation:
    """Crude but always-works classifier."""
    loc = _HtmlLocation(parser_used="regex")

    # v10.19 (icanteen TP): check <script> containment BEFORE HTML comment.
    # Legacy pages wrap inline JS in <script><!-- ... // --></script>; that
    # <!-- --> is INVISIBLE to the JS parser — code inside still executes.
    # If we matched the comment first we'd mislabel a real script-context
    # reflection as html_comment (FP category) and miss script XSS.
    opens = [m.end() for m in _RE_SCRIPT_OPEN.finditer(body)]
    closes = [m.start() for m in _RE_SCRIPT_CLOSE.finditer(body)]
    for o in opens:
        next_c = next((c for c in closes if c > o), len(body))
        if o <= marker_offset < next_c:
            loc.context = Context.HTML_RAWTEXT
            loc.sub_context = SubContext.TEXT_IN_RAWTEXT_SCRIPT
            loc.element_tag = "script"
            loc.container_start = o
            loc.container_end = next_c
            return loc

    # In comment? (only if NOT inside a <script> block — handled above)
    for m in _RE_COMMENT.finditer(body):
        if m.start() <= marker_offset < m.end():
            loc.context = Context.HTML_COMMENT
            loc.container_start = m.start()
            loc.container_end = m.end()
            return loc

    # In <style> block?
    opens = [m.end() for m in _RE_STYLE_OPEN.finditer(body)]
    closes = [m.start() for m in _RE_STYLE_CLOSE.finditer(body)]
    for o in opens:
        next_c = next((c for c in closes if c > o), len(body))
        if o <= marker_offset < next_c:
            loc.context = Context.CSS
            loc.sub_context = SubContext.CSS_VALUE
            loc.element_tag = "style"
            loc.container_start = o
            loc.container_end = next_c
            return loc

    # In attribute? Look left for `name="...` without an intervening `>`
    tag_start = body.rfind("<", 0, marker_offset)
    tag_end = body.find(">", marker_offset)
    if tag_start != -1 and tag_end != -1 and tag_end > marker_offset:
        tag_content = body[tag_start:marker_offset]
        # Find the last attr= before marker
        last_attr = None
        for m in _RE_ATTR_NEAR.finditer(tag_content):
            last_attr = m
        if last_attr is not None:
            attr_name = last_attr.group("name").lower()
            quote = last_attr.group("q") or None
            loc.context = Context.HTML_ATTR
            loc.attribute_name = attr_name
            loc.quote_char = quote
            loc.sub_context = _classify_attr_subcontext(
                attr_name, quote, None)
            # Also grab the enclosing element tag
            tm = re.match(r"<([a-zA-Z][\w:-]*)", body[tag_start:tag_start + 50])
            if tm:
                loc.element_tag = tm.group(1).lower()
            return loc

    # Default: HTML text
    loc.context = Context.HTML_TEXT
    loc.sub_context = SubContext.TEXT_NORMAL
    return loc


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def analyze_html(body: str, marker_offset: int) -> _HtmlLocation:
    """Run tree-sitter → regex fallback chain and return the best location."""
    loc = _ts_analyze_html(body, marker_offset)
    if loc is None or loc.context == Context.UNKNOWN:
        loc = _regex_fallback(body, marker_offset)
    # Optional: enrich element_path with bs4 (non-authoritative, just nicer report)
    _bs4_enrich_path(body, marker_offset, loc)
    return loc
