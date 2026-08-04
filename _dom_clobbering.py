"""
_dom_clobbering.py
==================
DOM Clobbering → XSS chain detector (v10.4, 2026 priority).

Background
----------
DOM Clobbering is a 2026 mainstream attack vector (Intigriti March 2026 CTF,
Cure53 research). Attacker injects HTML elements with `name=` / `id=` /
`for=` attributes that "clobber" JavaScript globals. When the application
later reads those globals expecting an object, it gets an HTMLElement instead,
and member access (`config.dataset.next`, `mGlobals.scriptUrl`) returns
attacker-controlled values.

Three exploitable patterns
--------------------------

PATTERN A: Sanitizer config that doesn't strip name/id/for attributes
   DOMPurify.sanitize(html);   // default — name/id/for ALLOWED
   DOMPurify.sanitize(html, {ALLOW_TAGS: ['form', 'a', 'div']});
   When user input is sanitized but `name=`/`id=` aren't forbidden, attacker
   can inject `<form name="authConfig" data-next="//evil.com">` and clobber.
   FIX: explicit FORBID_ATTR: ['name', 'id', 'for'].

PATTERN B: Conditional check on potentially-clobbered global
   if (window.config) { ... config.dataset.next ... }
   if (auth.allowed) { ... }
   The `if` check passes when `config` is an HTMLElement (truthy), then
   `.dataset.next` returns user-controlled value from data-next attribute.
   FIX: typeof check + own-property assertion.

PATTERN C: Member access on file-level identifier with no assignment
   const next = appConfig.redirectUrl;
   eval(globalCfg.script);
   When `appConfig` is read but never assigned in the file, it could be
   defined elsewhere — or clobbered via injected HTML if a sanitizer is
   permissive.

Public API
----------
    detect_clobbering_sinks(js_source, source_name) -> List[ClobberingSink]
        AST scan for unowned-global property access.

    detect_sanitizer_misconfig(js_source, source_name) -> List[SanitizerIssue]
        Find DOMPurify.sanitize() calls without FORBID_ATTR for name/id/for.

    build_clobbering_report(...) -> ClobberingReport
        Combined: sinks + sanitizer issues + form/anchor injection points.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("xss_grenade.dom_clobbering")

try:
    import esprima
    _ESPRIMA_AVAILABLE = True
except ImportError:
    _ESPRIMA_AVAILABLE = False
    esprima = None


# ──────────────────────────────────────────────────────────────────────────────
# DATA TYPES
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ClobberingSink:
    """A property read on a global that could be clobbered via DOM injection."""
    file: str
    line: int
    col: int
    pattern: str         # "window.X access", "global X used", "X.dataset access"
    receiver: str        # the identifier (e.g. "authConfig", "globalCfg")
    property_chain: str  # "dataset.next", "scriptUrl" — what's read after receiver
    sink_kind: str       # "code-exec" / "url-redirect" / "html-sink" / "config-toggle"
    snippet: str = ""
    severity: str = "high"
    confidence: float = 0.5


@dataclass
class SanitizerIssue:
    """A sanitizer call that doesn't forbid clobberable attributes."""
    file: str
    line: int
    col: int
    sanitizer: str       # "DOMPurify" / "sanitize-html" / "Sanitizer API"
    issue: str           # "missing FORBID_ATTR for name/id/for"
    snippet: str = ""
    severity: str = "high"
    confidence: float = 0.7


@dataclass
class ClobberingReport:
    """Combined analysis for one target."""
    url: str = ""
    sinks: List[ClobberingSink] = field(default_factory=list)
    sanitizer_issues: List[SanitizerIssue] = field(default_factory=list)

    @property
    def has_chain(self) -> bool:
        """True if a sanitizer issue AND a clobberable sink exist IN THE SAME FILE.

        v10.76 FP fix: the report pools sinks + issues from ALL inline and
        external scripts of a page, so the old `bool(sinks and issues)` stitched
        an app-inline DOMPurify.sanitize() call to an unrelated `x.src`/`x.dataset`
        read inside a vendor bundle (jQuery/owl.carousel) — a spurious HIGH with
        no data flow. Require the sanitizer issue and the sink to live in the
        SAME file before claiming a chain."""
        if not (self.sinks and self.sanitizer_issues):
            return False
        sink_files = {s.file for s in self.sinks}
        return any(i.file in sink_files for i in self.sanitizer_issues)

    def same_file_pairs(self):
        """Yield (sink, issue) pairs that originate from the SAME file — the only
        pairs the consumer should emit as a chain."""
        by_file = {}
        for i in self.sanitizer_issues:
            by_file.setdefault(i.file, []).append(i)
        for s in self.sinks:
            for i in by_file.get(s.file, []):
                yield s, i


# ──────────────────────────────────────────────────────────────────────────────
# AST HELPERS (mirror _proto_pollution_analyzer style)
# ──────────────────────────────────────────────────────────────────────────────

def _node_type(node) -> str:
    return getattr(node, "type", "") or ""


def _loc_line(node) -> int:
    try:
        return node.loc.start.line
    except (AttributeError, TypeError):
        return 0


def _loc_col(node) -> int:
    try:
        return node.loc.start.column
    except (AttributeError, TypeError):
        return 0


def _walk(node, callback, depth=0, max_depth=200):
    if depth > max_depth or not hasattr(node, "type"):
        return
    callback(node)
    SKIP = {"type", "loc", "range", "name", "value", "raw", "kind",
            "operator", "regex", "computed", "shorthand", "method",
            "prefix", "delegate", "async", "generator", "static", "directive"}
    for attr in dir(node):
        if attr.startswith("_") or attr in SKIP:
            continue
        try:
            v = getattr(node, attr)
        except Exception:
            continue
        if isinstance(v, list):
            for item in v:
                _walk(item, callback, depth + 1, max_depth)
        elif hasattr(v, "type"):
            _walk(v, callback, depth + 1, max_depth)


def _snippet_of(source_text: str, node, max_len: int = 200) -> str:
    try:
        if hasattr(node, "range") and node.range:
            s, e = node.range
            return source_text[s:e][:max_len].replace("\n", " ")
    except Exception:
        pass
    return ""


def _try_parse(source_code: str):
    """Parse JS, return AST or None. Tolerant — try Script then Module."""
    try:
        return esprima.parseScript(
            source_code, options={"loc": True, "range": True, "tolerant": True}
        )
    except Exception:
        try:
            return esprima.parseModule(
                source_code, options={"loc": True, "range": True, "tolerant": True}
            )
        except Exception:
            return None


# ──────────────────────────────────────────────────────────────────────────────
# CLOBBERABLE-SINK DETECTION
# ──────────────────────────────────────────────────────────────────────────────

# Property names that, when read after a clobberable identifier, lead to
# attacker-controlled values. From real-world chains (Intigriti CTFs, Cure53):
_CLOBBERABLE_TARGET_PROPS: Dict[str, Tuple[str, str]] = {
    # HTMLElement.dataset — auto-populated from data-* attributes
    "dataset":       ("config-leak",  "high"),
    # HTMLAnchorElement.href — set via injected <a id="X" href="...">
    "href":          ("url-redirect", "high"),
    # HTMLImageElement.src
    "src":           ("url-redirect", "high"),
    # HTMLFormElement.action
    "action":        ("url-redirect", "high"),
    # HTMLFormElement.name — clobbers window.<name>
    # (used as receiver, not a "leaf" property)
}

# Methods that, when called on a clobbered receiver, exec code or change DOM
_CLOBBERABLE_SINK_CALLS: Dict[str, Tuple[str, str]] = {
    # eval(X.Y), Function(X.Y), new Function(X.Y) — covered in PP detector,
    # we additionally flag them as DOM clobbering candidates
    "eval":          ("code-exec",     "critical"),
    "Function":      ("code-exec",     "critical"),
    # Runtime appends — script.src = X.Y → loads attacker-controlled JS
    "appendChild":   ("dom-mutation",  "high"),
    "createElement": ("dom-mutation",  "medium"),
}


def detect_clobbering_sinks(source_code: str,
                             source_name: str = "<inline>"
                             ) -> List[ClobberingSink]:
    """Scan JS for property reads on identifiers that could be DOM-clobbered.

    Heuristic: if `X` is read but never assigned in the file, AND we read
    `X.Y` where Y is a known clobberable property (dataset, href, src), then
    `X` is a clobbering candidate.
    """
    if not _ESPRIMA_AVAILABLE or not source_code or not source_code.strip():
        return []
    tree = _try_parse(source_code)
    if tree is None:
        return []

    findings: List[ClobberingSink] = []

    # Phase 1: collect all identifiers ASSIGNED in this file.
    # These are owned globals / locals — NOT clobberable.
    assigned_idents: Set[str] = set()

    def collect_assignments(node):
        t = _node_type(node)
        if t == "VariableDeclarator":
            id_ = node.id
            if id_ is not None and _node_type(id_) == "Identifier":
                assigned_idents.add(id_.name)
        elif t == "AssignmentExpression":
            left = node.left
            if left is not None and _node_type(left) == "Identifier":
                assigned_idents.add(left.name)
            elif left is not None and _node_type(left) == "MemberExpression":
                # window.X = ... is an assignment, X is owned
                obj = left.object
                prop = left.property
                if (obj is not None and _node_type(obj) == "Identifier"
                        and obj.name in ("window", "globalThis", "self")
                        and prop is not None
                        and _node_type(prop) == "Identifier"):
                    assigned_idents.add(prop.name)
        elif t == "FunctionDeclaration":
            id_ = node.id
            if id_ is not None and _node_type(id_) == "Identifier":
                assigned_idents.add(id_.name)
        elif t == "ClassDeclaration":
            id_ = node.id
            if id_ is not None and _node_type(id_) == "Identifier":
                assigned_idents.add(id_.name)
        elif t in ("ImportDefaultSpecifier", "ImportSpecifier",
                    "ImportNamespaceSpecifier"):
            local = getattr(node, "local", None)
            if local is not None and _node_type(local) == "Identifier":
                assigned_idents.add(local.name)
        elif t == "FunctionExpression" or t == "ArrowFunctionExpression":
            params = getattr(node, "params", None) or []
            for p in params:
                if p is not None and _node_type(p) == "Identifier":
                    assigned_idents.add(p.name)

    _walk(tree, collect_assignments)

    # Collect MemberExpression nodes that are LHS of assignments — those are
    # writes, not reads. DOM Clobbering exploits READS from clobbered globals
    # (attacker injects DOM, code reads the clobbered value). Writing TO a
    # property doesn't read anything, so skip those.
    lhs_member_node_ids: Set[int] = set()

    def collect_lhs_assignments(node):
        if _node_type(node) == "AssignmentExpression":
            left = node.left
            if left is not None and _node_type(left) == "MemberExpression":
                lhs_member_node_ids.add(id(left))

    _walk(tree, collect_lhs_assignments)

    # Pre-baked safe identifiers: built-ins, browser globals, common imports.
    # These are never clobberable in practice (read-only globals or attached
    # to window via spec-defined slots that DOM Clobbering can't override).
    SAFE_IDENTS = {
        # JavaScript built-ins
        "Object", "Array", "String", "Number", "Boolean", "Symbol", "Math",
        "Date", "RegExp", "Error", "JSON", "Promise", "Map", "Set",
        "WeakMap", "WeakSet", "ArrayBuffer", "DataView", "Proxy", "Reflect",
        "Function", "console", "Intl", "fetch", "Response", "Request",
        "URL", "URLSearchParams", "FormData", "Blob", "File", "FileReader",
        "TextEncoder", "TextDecoder", "AbortController", "Headers",
        # Browser-spec window properties (cannot be clobbered via DOM)
        "location", "navigator", "history", "screen", "performance",
        "localStorage", "sessionStorage", "indexedDB", "crypto",
        "innerWidth", "innerHeight", "outerWidth", "outerHeight",
        "scrollX", "scrollY", "pageXOffset", "pageYOffset", "devicePixelRatio",
        "alert", "confirm", "prompt", "open", "close", "focus", "blur",
        "setTimeout", "setInterval", "clearTimeout", "clearInterval",
        "requestAnimationFrame", "cancelAnimationFrame",
        "addEventListener", "removeEventListener", "dispatchEvent",
        "postMessage", "atob", "btoa", "encodeURIComponent", "decodeURIComponent",
        "encodeURI", "decodeURI", "parseInt", "parseFloat", "isNaN", "isFinite",
        # Document-spec properties
        "body", "head", "title", "documentElement", "URL", "domain",
        "cookie", "referrer", "readyState", "currentScript",
        # Common library imports
        "$", "jQuery", "_", "lodash", "axios", "moment", "dayjs",
        "React", "ReactDOM", "Vue", "Angular", "Svelte", "DOMPurify",
        "process", "Buffer", "require", "module", "exports", "global",
        "__dirname", "__filename", "this", "arguments",
        # TypeScript helpers
        "any", "void", "never", "unknown",
    }

    def visit(node):
        if _node_type(node) != "MemberExpression":
            return
        if getattr(node, "computed", False):
            return
        # Skip LHS of assignments — those are writes (we want reads only)
        if id(node) in lhs_member_node_ids:
            return
        receiver = node.object
        prop = node.property
        if receiver is None or prop is None:
            return
        if _node_type(prop) != "Identifier":
            return
        prop_name = prop.name

        # Case 1: window.X.Y or document.X.Y where X is clobberable
        # The MemberExpression we see is X.Y; receiver is X.
        # If X was read off window/document as `window.X`, treat as clobber-suspect.
        recv_t = _node_type(receiver)
        if recv_t == "MemberExpression":
            # Pattern: window.<id>.<prop>
            outer_obj = receiver.object
            outer_prop = receiver.property
            if (outer_obj is not None and _node_type(outer_obj) == "Identifier"
                    and outer_obj.name in ("window", "document",
                                            "globalThis", "self")
                    and outer_prop is not None
                    and _node_type(outer_prop) == "Identifier"
                    and not getattr(receiver, "computed", False)):
                global_name = outer_prop.name
                if global_name in SAFE_IDENTS or global_name in assigned_idents:
                    return
                if prop_name in _CLOBBERABLE_TARGET_PROPS:
                    sink_kind, severity = _CLOBBERABLE_TARGET_PROPS[prop_name]
                    findings.append(ClobberingSink(
                        file=source_name,
                        line=_loc_line(node), col=_loc_col(node),
                        pattern=(f"window.{global_name}.{prop_name} "
                                 f"(unowned global)"),
                        receiver=global_name,
                        property_chain=prop_name,
                        sink_kind=sink_kind,
                        severity=severity,
                        confidence=0.65,
                        snippet=_snippet_of(source_code, node),
                    ))
        elif recv_t == "Identifier":
            recv_name = receiver.name
            # Skip safe / owned receivers
            if recv_name in SAFE_IDENTS or recv_name in assigned_idents:
                return
            # window/document/etc. handled above — skip bare uses
            if recv_name in ("window", "document", "globalThis", "self",
                              "this", "globalThis"):
                return
            # Now we have an unowned identifier — flag if accessing
            # a clobberable property
            if prop_name in _CLOBBERABLE_TARGET_PROPS:
                sink_kind, severity = _CLOBBERABLE_TARGET_PROPS[prop_name]
                findings.append(ClobberingSink(
                    file=source_name,
                    line=_loc_line(node), col=_loc_col(node),
                    pattern=f"{recv_name}.{prop_name} (unowned global)",
                    receiver=recv_name,
                    property_chain=prop_name,
                    sink_kind=sink_kind,
                    severity=severity,
                    confidence=0.55,
                    snippet=_snippet_of(source_code, node),
                ))

    _walk(tree, visit)

    # Pattern C: assignments like `script.src = unowned.X.Y` or `eval(unowned.X)`
    # where the right-hand side reads from an unowned global. The receiver
    # might be ANY property name (not just dataset/href), but the SINK is
    # what makes it dangerous.
    DANGEROUS_LHS_SINK_PROPS = {
        "src":      ("dom-mutation", "high"),     # script.src, iframe.src
        "href":     ("url-redirect", "high"),     # a.href, link.href
        "innerHTML":("html-sink",    "critical"),
        "outerHTML":("html-sink",    "critical"),
        "action":   ("url-redirect", "high"),
    }

    def is_unowned_member_chain(node) -> Optional[Tuple[str, str]]:
        """If node is X.Y or X.Y.Z (or window.X.Y.Z) where X is an unowned
        identifier, return (X, full_chain_str). Else None.

        Peels off `window.` / `document.` / `globalThis.` / `self.` prefix —
        what's clobberable is the property AFTER that prefix."""
        if node is None or _node_type(node) != "MemberExpression":
            return None
        chain = []
        cur = node
        while cur is not None and _node_type(cur) == "MemberExpression":
            prop = cur.property
            if (prop is not None and _node_type(prop) == "Identifier"
                    and not getattr(cur, "computed", False)):
                chain.append(prop.name)
            else:
                return None
            cur = cur.object
        if cur is None or _node_type(cur) != "Identifier":
            return None
        root = cur.name
        # Peel window/document/etc. prefix → effective receiver is next prop
        if root in ("window", "document", "globalThis", "self"):
            if not chain:
                return None
            recv = chain.pop()  # next-most receiver
        else:
            recv = root
        if (recv in SAFE_IDENTS or recv in assigned_idents
                or recv in ("window", "document", "globalThis", "self",
                             "this")):
            return None
        chain_str = recv + "." + ".".join(reversed(chain)) if chain else recv
        return (recv, chain_str)

    def visit_pattern_c(node):
        t = _node_type(node)
        if t == "AssignmentExpression":
            left = node.left
            right = node.right
            if (left is not None and _node_type(left) == "MemberExpression"
                    and not getattr(left, "computed", False)):
                left_prop = left.property
                if (left_prop is not None
                        and _node_type(left_prop) == "Identifier"
                        and left_prop.name in DANGEROUS_LHS_SINK_PROPS):
                    chain = is_unowned_member_chain(right)
                    if chain is not None:
                        recv, chain_str = chain
                        sink_kind, severity = DANGEROUS_LHS_SINK_PROPS[left_prop.name]
                        findings.append(ClobberingSink(
                            file=source_name,
                            line=_loc_line(node), col=_loc_col(node),
                            pattern=(f"<element>.{left_prop.name} = "
                                      f"{chain_str} (unowned)"),
                            receiver=recv,
                            property_chain=chain_str,
                            sink_kind=sink_kind,
                            severity=severity,
                            confidence=0.6,
                            snippet=_snippet_of(source_code, node),
                        ))
        elif t == "CallExpression":
            callee = node.callee
            sink_label = None
            if callee is not None and _node_type(callee) == "Identifier":
                if callee.name in ("eval", "Function"):
                    sink_label = f"{callee.name}(...)"
            if sink_label is None:
                return
            args = getattr(node, "arguments", None) or []
            if not args:
                return
            chain = is_unowned_member_chain(args[0])
            if chain is not None:
                recv, chain_str = chain
                findings.append(ClobberingSink(
                    file=source_name,
                    line=_loc_line(node), col=_loc_col(node),
                    pattern=f"{sink_label} on {chain_str} (unowned)",
                    receiver=recv,
                    property_chain=chain_str,
                    sink_kind="code-exec",
                    severity="critical",
                    confidence=0.7,
                    snippet=_snippet_of(source_code, node),
                ))

    _walk(tree, visit_pattern_c)
    return findings


# (sentinel marker for unique replace)


# ──────────────────────────────────────────────────────────────────────────────
# SANITIZER MISCONFIGURATION DETECTION
# ──────────────────────────────────────────────────────────────────────────────

# Does the config object (esprima ObjectExpression) include a property called
# FORBID_ATTR with array containing all of name/id/for?
def _config_forbids_clobber_attrs(config_node) -> bool:
    """True if the DOMPurify config defeats DOM clobbering. v10.76: safe when ANY
    of (was: only FORBID_ATTR):
      - SANITIZE_NAMED_PROPS is truthy — DOMPurify's DEDICATED anti-clobbering
        option (namespaces name/id so clobbering can't reach globals), OR
      - FORBID_ATTR forbids all of name/id/for, OR
      - an ALLOWED_ATTR allowlist is present that does NOT permit name/id/for
        (allowlist mode strips everything else, so those attrs never survive)."""
    if config_node is None or _node_type(config_node) != "ObjectExpression":
        return False
    forbid_attr_value = None
    allowed_attr_value = None
    sanitize_named_props = False
    for prop in (getattr(config_node, "properties", None) or []):
        key = getattr(prop, "key", None)
        if key is None:
            continue
        key_name = None
        if _node_type(key) == "Identifier":
            key_name = key.name
        elif _node_type(key) == "Literal":
            key_name = getattr(key, "value", None)
        val = getattr(prop, "value", None)
        if key_name == "FORBID_ATTR":
            forbid_attr_value = val
        elif key_name == "ALLOWED_ATTR":
            allowed_attr_value = val
        elif key_name == "SANITIZE_NAMED_PROPS":
            if _node_type(val) == "Literal" and getattr(val, "value", None) is True:
                sanitize_named_props = True

    if sanitize_named_props:
        return True

    def _array_lower_set(arr) -> Set[str]:
        out: Set[str] = set()
        if arr is not None and _node_type(arr) == "ArrayExpression":
            for elem in (getattr(arr, "elements", None) or []):
                if elem is not None and _node_type(elem) == "Literal":
                    v = getattr(elem, "value", None)
                    if isinstance(v, str):
                        out.add(v.lower())
        return out

    # FORBID_ATTR blocks all three clobber attributes.
    if {"name", "id", "for"}.issubset(_array_lower_set(forbid_attr_value)):
        return True

    # ALLOWED_ATTR allowlist that does not include name/id/for → they're stripped.
    if allowed_attr_value is not None and _node_type(allowed_attr_value) == "ArrayExpression":
        if not ({"name", "id", "for"} & _array_lower_set(allowed_attr_value)):
            return True

    return False


def detect_sanitizer_misconfig(source_code: str,
                                source_name: str = "<inline>"
                                ) -> List[SanitizerIssue]:
    """Find DOMPurify.sanitize() / Sanitizer API calls that don't forbid
    name/id/for attributes — meaning user input could inject clobberable
    HTML elements."""
    if not _ESPRIMA_AVAILABLE or not source_code or not source_code.strip():
        return []
    tree = _try_parse(source_code)
    if tree is None:
        return []

    findings: List[SanitizerIssue] = []
    seen: Set[Tuple[int, int]] = set()

    def visit(node):
        if _node_type(node) != "CallExpression":
            return
        callee = node.callee
        if callee is None or _node_type(callee) != "MemberExpression":
            return
        prop = callee.property
        obj = callee.object
        if (prop is None or _node_type(prop) != "Identifier"
                or prop.name != "sanitize"):
            return
        # Check receiver is DOMPurify (or known sanitizer)
        sanitizer = None
        if obj is not None and _node_type(obj) == "Identifier":
            if obj.name in ("DOMPurify", "purify", "sanitizer"):
                sanitizer = obj.name
        if sanitizer is None:
            return
        # Look at arguments — second arg is config object
        args = getattr(node, "arguments", None) or []
        config = args[1] if len(args) >= 2 else None
        if _config_forbids_clobber_attrs(config):
            return  # safe — name/id/for are forbidden
        loc_key = (_loc_line(node), _loc_col(node))
        if loc_key in seen:
            return
        seen.add(loc_key)
        findings.append(SanitizerIssue(
            file=source_name,
            line=_loc_line(node), col=_loc_col(node),
            sanitizer=sanitizer,
            issue=("config does not forbid name/id/for — DOM Clobbering "
                   "via injected <form name=X> / <a id=X> still possible"),
            severity="high",
            confidence=0.7,
            snippet=_snippet_of(source_code, node),
        ))

    _walk(tree, visit)
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# COMBINED REPORT
# ──────────────────────────────────────────────────────────────────────────────

def build_clobbering_report(url: str,
                             inline_scripts: Optional[List[str]] = None,
                             external_scripts: Optional[Dict[str, str]] = None
                             ) -> ClobberingReport:
    """One-shot analysis: detect clobberable sinks + sanitizer misconfigs."""
    report = ClobberingReport(url=url)
    for body in (inline_scripts or []):
        report.sinks.extend(detect_clobbering_sinks(body, url + "#inline"))
        report.sanitizer_issues.extend(
            detect_sanitizer_misconfig(body, url + "#inline"))
    for ext_url, src in (external_scripts or {}).items():
        report.sinks.extend(detect_clobbering_sinks(src, ext_url))
        report.sanitizer_issues.extend(detect_sanitizer_misconfig(src, ext_url))
    return report
