"""
_proto_pollution_analyzer.py
=============================
Prototype Pollution → XSS chain detector (v10, 2026 priority).

Background
----------
Prototype Pollution (PP) is a JS-specific class of vulnerabilities where
attacker-controlled input modifies Object.prototype, affecting EVERY object
in the application. By itself harmless; combined with a "gadget" (any code
reading a property from an unowned object), it becomes RCE/XSS.

CVE-2026-41238 (April 2026, before week)
----------------------------------------
DOMPurify 3.0.1 through 3.3.x (patched in 3.4.0 — see _dompurify_cve_feed.py,
the authoritative source) has the line:
    CUSTOM_ELEMENT_HANDLING = cfg.CUSTOM_ELEMENT_HANDLING || {};
The fallback `{}` inherits from Object.prototype. If attacker has polluted
Object.prototype.tagNameCheck = /.*/ and attributeNameCheck = /.*/, DOMPurify
allows ARBITRARY custom elements (with hyphens) and ARBITRARY attributes —
including event handlers like onfocus.

Result: <x-x onfocus=alert(1) tabindex=0 autofocus> survives sanitization.

Detection strategy
------------------
Phase 1 (static AST): Find pollution SOURCES — recursive merge functions
  with user-controlled input.
    Vulnerable: lodash.merge, $.extend(true,…), deepmerge, custom for…in
  loops without hasOwnProperty / __proto__ filter.
    Safe: Object.assign (shallow only), explicit __proto__ filter.

Phase 2 (static AST): Find pollution GADGETS — properties read from objects
  without own-property check, where polluted value flows to dangerous sink.
    Known gadgets: innerHTML, outerHTML, src, href, transport_url, body,
    _body, content-type, sanitize, escapeHTML, tagNameCheck (DOMPurify!),
    attributeNameCheck (DOMPurify!), CUSTOM_ELEMENT_HANDLING.

Phase 3 (DOMPurify version detection): Look for DOMPurify in page scripts,
  extract version, flag if 3.0.1 ≤ version < 3.4.0 → CVE-2026-41238 chain
  candidate.

Phase 4 (dynamic probe — handed off to DOM v6):
  Append `?__proto__[XSGS_PP_PROBE]=PWNED` to URL, check in Chromium if
  Object.prototype.XSGS_PP_PROBE === "PWNED" after page load.

Public API
----------

    detect_pollution_sources(js_source, source_name) -> List[PPSource]
    detect_pollution_gadgets(js_source, source_name) -> List[PPGadget]
    detect_dompurify_version(js_source) -> Optional[str]
    classify_dompurify_version(ver_str) -> Optional[str]   # "vulnerable"/"safe"
    build_pollution_report(...) -> PPReport
    make_pp_probe_url(target_url, probe_token) -> str
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("xss_grenade.proto_pollution")

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
class PPSource:
    """A pollution SOURCE — code that recursively merges user input into objects."""
    file: str
    line: int
    col: int
    pattern: str          # "lodash.merge", "$.extend(true)", "deepmerge", "custom-for-in"
    snippet: str = ""
    severity: str = "medium"   # info / medium / high
    confidence: float = 0.7
    arg_origin: str = ""       # "user-input" if we can prove arg is tainted, else "unknown"


@dataclass
class PPGadget:
    """A pollution GADGET — property read from object without own-property check,
    where the property name is known to be exploitable."""
    file: str
    line: int
    col: int
    property_name: str    # "innerHTML", "tagNameCheck", "transport_url", ...
    sink_kind: str        # "dompurify-cve-2026-41238" / "html-sink" / "url-sink" / "config-sink"
    snippet: str = ""
    severity: str = "high"
    confidence: float = 0.5


@dataclass
class DOMPurifyDep:
    """Detected DOMPurify usage in a JS source."""
    file: str
    version: Optional[str] = None     # "3.2.1" if extracted, else None
    line: int = 0
    is_vulnerable: bool = False       # True if any CVE matches (backward compat)
    confidence: float = 0.6
    # v10.10: data-driven CVE matching — list of dicts from CVE feed.
    # Each dict has: cve, severity, vector, description, bypass_payload, reference.
    # Empty list = safe version OR unknown version.
    matched_cves: List[Dict] = field(default_factory=list)


@dataclass
class PPReport:
    """Combined pollution analysis for one target."""
    url: str = ""
    sources: List[PPSource] = field(default_factory=list)
    gadgets: List[PPGadget] = field(default_factory=list)
    dompurify_deps: List[DOMPurifyDep] = field(default_factory=list)

    @property
    def has_chain(self) -> bool:
        """True if both source and gadget exist — chained exploit possible."""
        return bool(self.sources and (self.gadgets or self.has_vulnerable_dompurify))

    @property
    def has_vulnerable_dompurify(self) -> bool:
        return any(d.is_vulnerable for d in self.dompurify_deps)


# ──────────────────────────────────────────────────────────────────────────────
# AST HELPERS (mirror _static_js_analyzer style)
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


# ──────────────────────────────────────────────────────────────────────────────
# POLLUTION SOURCES — recursive merge patterns
# ──────────────────────────────────────────────────────────────────────────────

# Member-expression callees that match "<receiver>.<method>"
# where method is known to recursively merge.
_RECURSIVE_MERGE_METHODS = {
    "merge":          ("lodash.merge",        "high",   0.85),
    "mergeWith":      ("lodash.mergeWith",    "high",   0.80),
    "defaultsDeep":   ("lodash.defaultsDeep", "high",   0.80),
    # jQuery $.extend with first arg true = deep merge
    # (handled separately because we need to inspect first argument)
    "set":            ("lodash.set",          "medium", 0.50),  # _.set("a.b.c", v)
    "setWith":        ("lodash.setWith",      "medium", 0.50),
}

# Identifier callees (top-level functions, not member expressions)
_RECURSIVE_MERGE_IDENTS = {
    "deepmerge":      ("deepmerge",           "high",   0.80),
    "deepMerge":      ("deepMerge",           "high",   0.80),
    "extend":         ("extend",              "medium", 0.55),  # ambiguous
    "mergeRecursive": ("mergeRecursive",      "high",   0.80),
}


def _detect_jquery_deep_extend(node) -> Optional[Tuple[str, str, float]]:
    """$.extend(true, target, src) is deep merge. Return (label, sev, conf)."""
    if _node_type(node) != "CallExpression":
        return None
    callee = node.callee
    if _node_type(callee) != "MemberExpression":
        return None
    prop = callee.property
    if _node_type(prop) != "Identifier" or prop.name != "extend":
        return None
    args = node.arguments or []
    if not args:
        return None
    first = args[0]
    if _node_type(first) == "Literal" and getattr(first, "value", None) is True:
        return ("$.extend(true, ...)", "high", 0.85)
    return None


def _is_user_input_arg(node) -> bool:
    """Heuristic: does this AST node look like user-controlled input?
    Catches obvious cases (req.query.*, req.body, JSON.parse(req.…))."""
    if node is None:
        return False
    t = _node_type(node)
    if t == "MemberExpression":
        # Walk receiver chain looking for "req" identifier
        cur = node
        chain = []
        while cur is not None:
            ct = _node_type(cur)
            if ct == "Identifier":
                chain.append(cur.name)
                break
            elif ct == "MemberExpression":
                if _node_type(cur.property) == "Identifier":
                    chain.append(cur.property.name)
                cur = cur.object
            elif ct == "CallExpression":
                # JSON.parse(…) — descend into argument
                args = cur.arguments or []
                return any(_is_user_input_arg(a) for a in args)
            else:
                break
        # req.body, req.query.*, request.body, ctx.request.body, location.search …
        if "req" in chain or "request" in chain:
            return True
        if "location" in chain and any(p in chain for p in (
                "search", "hash", "href")):
            return True
    if t == "CallExpression":
        # JSON.parse(<user-input>) → user input
        callee = getattr(node, "callee", None)
        if callee is not None and _node_type(callee) == "MemberExpression":
            obj = callee.object
            prop = callee.property
            if (obj is not None and _node_type(obj) == "Identifier"
                    and obj.name == "JSON"
                    and prop is not None and _node_type(prop) == "Identifier"
                    and prop.name == "parse"):
                args = node.arguments or []
                return any(_is_user_input_arg(a) for a in args)
    return False


def _detect_unsafe_for_in(node, source_text: str) -> Optional[Tuple[str, str, float]]:
    """Detect for-in loops that copy properties without __proto__/hasOwnProperty
    filter. Pattern: for (key in src) { dst[key] = src[key]; }"""
    if _node_type(node) != "ForInStatement":
        return None
    body = getattr(node, "body", None)
    if body is None:
        return None

    # v10.76: resolve the loop variable name so we can require a keyed WRITE.
    key_name = None
    left = getattr(node, "left", None)
    if _node_type(left) == "VariableDeclaration":
        decls = getattr(left, "declarations", None) or []
        if decls and _node_type(getattr(decls[0], "id", None)) == "Identifier":
            key_name = decls[0].id.name
    elif _node_type(left) == "Identifier":
        key_name = left.name

    # v10.76 FP fix: a for-in that never writes a computed keyed property CANNOT
    # pollute a prototype. `for (k in o) total += o[k]` / `console.log(k)` are
    # read-only and safe — the old code flagged them. Require an assignment
    # `x[key] = …` that uses the loop variable before flagging.
    writes_key = {"v": False}

    def _chk(n):
        if writes_key["v"] or _node_type(n) != "AssignmentExpression":
            return
        lhs = getattr(n, "left", None)
        if _node_type(lhs) == "MemberExpression" and getattr(lhs, "computed", False):
            prop = getattr(lhs, "property", None)
            if key_name is None or (_node_type(prop) == "Identifier"
                                    and getattr(prop, "name", None) == key_name):
                writes_key["v"] = True

    _walk(body, _chk)
    if not writes_key["v"]:
        return None

    # v10.76: scan the FULL body for guards (was truncated at 400 chars, missing
    # guards placed later in the loop).
    body_text = _snippet_of(source_text, body, 4000)
    # Safe pattern: explicitly skips __proto__ / constructor / prototype
    skips_proto = any(s in body_text for s in (
        "__proto__", "'__proto__'", '"__proto__"',
        "'constructor'", '"constructor"',
        "'prototype'", '"prototype"',
    )) and ("continue" in body_text or "!==" in body_text or "!=" in body_text)
    # v10.76: recognize MODERN guards too — the ES2022 Object.hasOwn(obj,key)
    # idiom and Reflect.has / getOwnPropertyNames, not just legacy hasOwnProperty.
    has_owncheck = any(g in body_text for g in (
        "hasOwnProperty", "Object.hasOwn", "Reflect.has",
        "getOwnPropertyNames", "getOwnPropertyDescriptor",
    ))
    if skips_proto or has_owncheck:
        return None
    # No protection — flag
    return ("custom-for-in (no __proto__/hasOwnProperty filter)", "medium", 0.50)


# ── Custom URL parser pollution sources ───────────────────────────────────────
# PortSwigger lab pattern (DOM XSS via alternative prototype pollution vector):
#
#   const params = location.search.slice(1).split("&");
#   for (const p of params) {
#       const [k, v] = p.split("=");
#       const path = k.split(".");                   // ← split path component
#       let obj = config;
#       for (let i = 0; i < path.length - 1; i++) {  // ← recursive descent
#           obj = obj[path[i]] = obj[path[i]] || {}; // ← THIS is the source
#       }
#       obj[path[path.length - 1]] = v;
#   }
#
# Useful when: lodash/jQuery NOT used; site has its own URL parser. Detection
# relies on AST recognition of the recursive descent pattern + presence of
# location.search/hash + split('.') in the same function/file.
_RE_RECURSIVE_DESCENT_BODY = re.compile(
    r"obj\s*\[.*?\]\s*=\s*obj\s*\[.*?\]\s*\|\|\s*\{"
)


def _detect_recursive_descent_assign(node, source_text: str
                                      ) -> Optional[Tuple[str, str, float]]:
    """Detect: for (i = 0; i < path.length - 1; i++) {
                   obj = obj[path[i]] = obj[path[i]] || {};
               }
    This is the canonical "arbitrary property path → pollution" pattern used
    by custom URL parsers. PortSwigger labs use exactly this construct."""
    if _node_type(node) != "ForStatement":
        return None
    body = getattr(node, "body", None)
    if body is None:
        return None
    body_text = _snippet_of(source_text, body, 600)
    # Match pattern: obj[path[i]] = obj[path[i]] || {}
    if _RE_RECURSIVE_DESCENT_BODY.search(body_text):
        return (
            "custom URL parser (recursive descent obj[k] = obj[k] || {})",
            "high", 0.85,
        )
    return None


# Look for "split('.')" or "split('.')" or split(/\./) in source — signal of
# custom URL parser that processes dotted paths (PortSwigger lab pattern).
_RE_DOTTED_PATH_SPLIT = re.compile(
    r"""\.split\s*\(\s*(['"])\.\1\s*\)|\.split\s*\(\s*/\\?\.\s*/\s*\)"""
)


def _detect_dotted_path_url_parser(source_text: str
                                    ) -> Optional[Tuple[str, str, float]]:
    """File-level pattern: parser that splits keys by '.' AND reads
    location.search/hash AND performs a recursive property descent.

    v10.19 (FP fix — mossctyri/gapi): dřív stačilo split('.') + location.* →
    matchovalo to i Google gapi knihovnu (gapix.rpc), kde split naviguje
    window.frames pro postMessage routing, NE objektové property paths. Žádný
    pollution primitiv tam není. Zúženo:
      (1) MUSÍ být přítomný recursive-descent zápis  obj[k]=obj[k]||{}  nebo
          cur=cur[k]=cur[k]||{}  — to je teprve pollution primitiv,
      (2) VYLUČ frame-navigační / postMessage RPC knihovní kód (window.frames,
          contentWindow, HTMLIFrameElement, postMessage routing) — tam split
          chodí po oknech, ne po objektu,
      (3) VYLUČ zřejmý minifikovaný knihovní kód bez aplikačního pollution
          primitivu.
    """
    if not _RE_DOTTED_PATH_SPLIT.search(source_text):
        return None
    has_location_source = (
        "location.search" in source_text
        or "location.hash" in source_text
        or "window.location" in source_text
    )
    if not has_location_source:
        return None

    # (2) Frame-navigation / postMessage RPC → NENÍ prototype pollution.
    #     Typické pro gapi, OAuth iframe bridges, embed SDK.
    _FRAME_NAV_MARKERS = (
        "frames[", ".frames", "contentWindow", "HTMLIFrameElement",
        "postMessage", "getElementsByTagName(\"iframe\")",
        "getElementsByTagName('iframe')", "rpctoken", "gapix", "gapi.",
        ".opener", "window.top", "_.Ce", "iframe",
    )
    frame_hits = sum(1 for m in _FRAME_NAV_MARKERS if m in source_text)
    if frame_hits >= 2:
        # silný signál frame-navigačního / RPC kódu → ne pollution source
        return None

    # (1) Vyžaduj reálný recursive-descent zápis (pollution primitiv).
    #     obj[k] = obj[k] || {}   nebo   cur = cur[k] = cur[k] || {}
    #     Bez něj je split('.') jen rozdělení textu (verze, název, hostname).
    if not _RE_RECURSIVE_DESCENT_BODY.search(source_text):
        # zkus i variantu s tečkovým přiřazením do vnořeného objektu
        _alt_descent = re.search(
            r"""(\w+)\s*=\s*\1\s*\[\s*\w+\s*\]\s*=\s*\1\s*\[\s*\w+\s*\]\s*\|\|"""
            r"""|(\w+)\s*\[\s*\w+\s*\]\s*=\s*\2\s*\[\s*\w+\s*\]\s*\|\|\s*\{""",
            source_text)
        if not _alt_descent:
            return None

    return (
        "dotted-path URL parser (split('.') + location.* + recursive descent)",
        "high", 0.65,
    )


# v10.18 (FP#1 fix): built-in objects whose .set()/.setWith() are NOT lodash
# and CANNOT write to __proto__ / do recursive nested-key assignment. Matching
# `.set(` blindly produced false positives (e.g. URLSearchParams.set('lang',l)
# flagged as lodash.set). Resolve the receiver and disqualify these.
_BUILTIN_SET_RECEIVERS = frozenset({
    "URLSearchParams", "searchParams", "Map", "Set", "WeakMap", "WeakSet",
    "Headers", "FormData", "Reflect", "localStorage", "sessionStorage",
    "dataset", "style", "classList", "DOMTokenList", "Cache", "caches",
})

# Keys that CAN reach the prototype. If a .set/.setWith key is a string literal
# that is none of these, prototype pollution is impossible by construction.
_PROTO_KEYS = frozenset({"__proto__", "constructor", "prototype"})


def _resolve_receiver_name(callee) -> str:
    """Best-effort name of the object a member call is invoked on.

    For `a.b.set(...)` returns 'b'; for `foo.searchParams.set` returns
    'searchParams'; for `_.set` returns '_'. Empty string if not resolvable.
    """
    obj = getattr(callee, "object", None)
    if obj is None:
        return ""
    t = _node_type(obj)
    if t == "Identifier":
        return getattr(obj, "name", "") or ""
    if t == "MemberExpression":
        prop = getattr(obj, "property", None)
        if _node_type(prop) == "Identifier":
            return getattr(prop, "name", "") or ""
        # nested object's object (e.g. window.localStorage)
        inner = getattr(obj, "object", None)
        if _node_type(inner) == "Identifier":
            return getattr(inner, "name", "") or ""
    if t == "CallExpression":
        # e.g. new URLSearchParams(...).set  /  getMap().set
        inner_callee = getattr(obj, "callee", None)
        if _node_type(inner_callee) == "Identifier":
            return getattr(inner_callee, "name", "") or ""
        if _node_type(inner_callee) == "MemberExpression":
            p = getattr(inner_callee, "property", None)
            if _node_type(p) == "Identifier":
                return getattr(p, "name", "") or ""
    if t == "NewExpression":
        nc = getattr(obj, "callee", None)
        if _node_type(nc) == "Identifier":
            return getattr(nc, "name", "") or ""
    return ""


def _set_call_is_real_lodash_setter(node, method_name: str) -> bool:
    """For a `.set`/`.setWith` member call, decide whether it is plausibly a
    lodash setter (so it can be a PP source) rather than a built-in like
    URLSearchParams/Map/dataset, and whether the key could even reach the
    prototype. Returns False to DISQUALIFY (not a pollution source)."""
    if method_name not in ("set", "setWith"):
        return True  # other methods (merge etc.) handled elsewhere
    callee = getattr(node, "callee", None)
    recv = _resolve_receiver_name(callee)
    # 1) Receiver is a known built-in with a non-lodash .set → disqualify.
    if recv in _BUILTIN_SET_RECEIVERS:
        return False
    # 2) Hard disqualifier: if the key (first arg) is a string literal that is
    #    not a prototype-reaching key, pollution is impossible regardless.
    args = getattr(node, "arguments", None) or []
    if args:
        key = args[0]
        if _node_type(key) == "Literal":
            kval = getattr(key, "value", None)
            if isinstance(kval, str):
                # Dotted lodash path like "a.b.__proto__.x" still counts;
                # only disqualify when NO prototype token appears anywhere.
                if not any(pk in kval for pk in _PROTO_KEYS):
                    return False
    return True


def detect_pollution_sources(source_code: str,
                              source_name: str = "<inline>") -> List[PPSource]:
    """Scan JS for code patterns that can pollute Object.prototype."""
    if not _ESPRIMA_AVAILABLE or not source_code or not source_code.strip():
        return []
    try:
        tree = esprima.parseScript(
            source_code, options={"loc": True, "range": True, "tolerant": True}
        )
    except Exception:
        try:
            tree = esprima.parseModule(
                source_code, options={"loc": True, "range": True, "tolerant": True}
            )
        except Exception:
            return []

    findings: List[PPSource] = []

    def visit(node):
        t = _node_type(node)
        # 1. Member-expression recursive merges (lodash etc.)
        if t == "CallExpression":
            callee = node.callee
            if _node_type(callee) == "MemberExpression":
                prop = callee.property
                if _node_type(prop) == "Identifier" and prop.name in _RECURSIVE_MERGE_METHODS:
                    # v10.18 (FP#1): disqualify built-in .set receivers
                    # (URLSearchParams/Map/dataset/…) and literal non-proto keys
                    # before treating this as a lodash pollution source.
                    if not _set_call_is_real_lodash_setter(node, prop.name):
                        return  # not a pollution source — skip
                    label, sev, conf = _RECURSIVE_MERGE_METHODS[prop.name]
                    args = node.arguments or []
                    arg_origin = "unknown"
                    # Boost confidence if any argument is clearly user-input
                    if args and any(_is_user_input_arg(a) for a in args[1:] if a is not None):
                        conf = min(0.95, conf + 0.10)
                        arg_origin = "user-input"
                        if sev == "medium":
                            sev = "high"
                    findings.append(PPSource(
                        file=source_name, line=_loc_line(node), col=_loc_col(node),
                        pattern=label, severity=sev, confidence=conf,
                        snippet=_snippet_of(source_code, node),
                        arg_origin=arg_origin,
                    ))
            # 2. Identifier-callee functions (deepmerge, etc.)
            elif _node_type(callee) == "Identifier":
                name = callee.name
                if name in _RECURSIVE_MERGE_IDENTS:
                    label, sev, conf = _RECURSIVE_MERGE_IDENTS[name]
                    args = node.arguments or []
                    arg_origin = "unknown"
                    if args and any(_is_user_input_arg(a) for a in args if a is not None):
                        conf = min(0.95, conf + 0.10)
                        arg_origin = "user-input"
                        if sev == "medium":
                            sev = "high"
                    findings.append(PPSource(
                        file=source_name, line=_loc_line(node), col=_loc_col(node),
                        pattern=label, severity=sev, confidence=conf,
                        snippet=_snippet_of(source_code, node),
                        arg_origin=arg_origin,
                    ))
            # 3. $.extend(true, ...) jQuery deep merge
            jq = _detect_jquery_deep_extend(node)
            if jq is not None:
                label, sev, conf = jq
                args = node.arguments or []
                arg_origin = "unknown"
                if any(_is_user_input_arg(a) for a in args[1:]):
                    conf = min(0.95, conf + 0.10)
                    arg_origin = "user-input"
                findings.append(PPSource(
                    file=source_name, line=_loc_line(node), col=_loc_col(node),
                    pattern=label, severity=sev, confidence=conf,
                    snippet=_snippet_of(source_code, node),
                    arg_origin=arg_origin,
                ))
        # 4. Unsafe for-in loops
        if t == "ForInStatement":
            r = _detect_unsafe_for_in(node, source_code)
            if r is not None:
                label, sev, conf = r
                findings.append(PPSource(
                    file=source_name, line=_loc_line(node), col=_loc_col(node),
                    pattern=label, severity=sev, confidence=conf,
                    snippet=_snippet_of(source_code, node),
                    arg_origin="unknown",
                ))

        # 5. Custom URL parser — recursive descent (PortSwigger lab pattern)
        # for (i = 0; i < path.length - 1; i++) { obj = obj[path[i]] = obj[path[i]] || {}; }
        if t == "ForStatement":
            r = _detect_recursive_descent_assign(node, source_code)
            if r is not None:
                label, sev, conf = r
                # Boost confidence if location.search/hash is in same file
                if ("location.search" in source_code
                        or "location.hash" in source_code):
                    conf = min(0.95, conf + 0.10)
                    arg_origin = "user-input"
                else:
                    arg_origin = "unknown"
                findings.append(PPSource(
                    file=source_name, line=_loc_line(node), col=_loc_col(node),
                    pattern=label, severity=sev, confidence=conf,
                    snippet=_snippet_of(source_code, node),
                    arg_origin=arg_origin,
                ))

    _walk(tree, visit)

    # 6. File-level pattern: dotted-path URL parser (signal of custom parser).
    # Only emit if no recursive-descent / lodash source was found in file —
    # otherwise we'd double-count.
    if not findings:
        r = _detect_dotted_path_url_parser(source_code)
        if r is not None:
            label, sev, conf = r
            findings.append(PPSource(
                file=source_name, line=1, col=0,
                pattern=label, severity=sev, confidence=conf,
                snippet=_snippet_of(source_code, tree, 200) if hasattr(tree, "range") else "",
                arg_origin="user-input",
            ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# POLLUTION GADGETS — known exploitable property names
# ──────────────────────────────────────────────────────────────────────────────

# Property names that are known to be exploited via PP. Each maps to:
#   (sink_kind, severity, description)
_KNOWN_GADGET_PROPS: Dict[str, Tuple[str, str]] = {
    # CVE-2026-41238 — DOMPurify CUSTOM_ELEMENT_HANDLING bypass
    "tagNameCheck":            ("dompurify-cve-2026-41238", "high"),
    "attributeNameCheck":      ("dompurify-cve-2026-41238", "high"),
    "CUSTOM_ELEMENT_HANDLING": ("dompurify-cve-2026-41238", "high"),
    # Generic XSS gadgets — polluted prop flows to HTML sink
    "innerHTML":               ("html-sink",       "critical"),
    "outerHTML":               ("html-sink",       "critical"),
    "documentWrite":           ("html-sink",       "critical"),
    "transport_url":           ("url-sink",        "high"),
    # Express PP gadgets (server-side response confusion)
    "_body":                   ("express-confusion", "high"),
    # Sanitizer toggle gadgets — pollute sanitize=false to disable
    "sanitize":                ("sanitizer-toggle", "high"),
    "escapeHTML":              ("sanitizer-toggle", "high"),
    "ALLOW_UNKNOWN_PROTOCOLS": ("dompurify-toggle", "high"),
    "FORCE_BODY":              ("dompurify-toggle", "medium"),
    # Template engine gadgets (Handlebars, Pug)
    "pendingContent":          ("handlebars-rce",  "critical"),
    # Auth bypass gadgets
    "isAdmin":                 ("auth-bypass",     "high"),
}


def _receiver_is_dom_element(receiver) -> bool:
    """Walk receiver chain — return True if any node looks like a DOM element
    or window/document. innerHTML/outerHTML on these is a real DOM sink, not
    a pollutable property. (DOM sinks are caught by static_js_analyzer.)"""
    DOM_NAMES = {
        "document", "window", "self", "globalThis",
        "this",          # frequent class-method receiver, often DOM-related
        "el", "elem", "element", "node", "target",
        "container", "body", "head", "wrapper", "root",
    }
    cur = receiver
    depth = 0
    while cur is not None and depth < 8:
        t = _node_type(cur)
        if t == "Identifier":
            if cur.name in DOM_NAMES:
                return True
            # Names like buttonEl, divEl, headerNode, modalRoot
            n = cur.name
            if n.endswith(("El", "Elem", "Element", "Node", "Container",
                           "Wrapper", "Body", "Header", "Root", "Modal",
                           "Dialog", "Card", "Btn", "Button")):
                return True
            return False
        elif t == "MemberExpression":
            # document.body.innerHTML — first descend to property, then receiver
            prop = cur.property
            if prop is not None and _node_type(prop) == "Identifier":
                if prop.name in DOM_NAMES:
                    return True
            cur = cur.object
            depth += 1
        elif t == "CallExpression":
            # document.getElementById(...).innerHTML — recurse into callee
            cur = cur.callee
            depth += 1
        else:
            return False
    return False


def detect_pollution_gadgets(source_code: str,
                              source_name: str = "<inline>"
                              ) -> List[PPGadget]:
    """Scan JS for property reads matching known PP gadget names.

    We emit a gadget only when the property is read via member expression on
    an object that is NOT obviously a DOM element. innerHTML/outerHTML on
    a DOM element is a real sink (caught by static_js_analyzer); innerHTML
    on a plain `opts` / `config` is a PP gadget candidate."""
    if not _ESPRIMA_AVAILABLE or not source_code or not source_code.strip():
        return []
    try:
        tree = esprima.parseScript(
            source_code, options={"loc": True, "range": True, "tolerant": True}
        )
    except Exception:
        try:
            tree = esprima.parseModule(
                source_code, options={"loc": True, "range": True, "tolerant": True}
            )
        except Exception:
            return []

    findings: List[PPGadget] = []
    seen_locations: Set[Tuple[int, int, str]] = set()

    # Phase 1: collect all property names that are ASSIGNED in this file.
    # These are own properties — NOT pollution gadgets.
    assigned_props: Set[str] = set()

    def collect_assignments(node):
        t = _node_type(node)
        if t == "AssignmentExpression":
            left = node.left
            if left is not None and _node_type(left) == "MemberExpression":
                if not getattr(left, "computed", False):
                    p = left.property
                    if p is not None and _node_type(p) == "Identifier":
                        assigned_props.add(p.name)
        elif t == "Property":
            # In ObjectExpression literal: { foo: ... } — `foo` is owned
            key = getattr(node, "key", None)
            if key is not None and _node_type(key) == "Identifier":
                assigned_props.add(key.name)

    _walk(tree, collect_assignments)

    # Phase 1b: locations of MemberExpressions used as a CALL CALLEE
    # (e.g. DOMPurify.sanitize(x), utils.escapeHTML(v)). Calling a method is an
    # invocation of that object's own function — NOT a read of a prototype-
    # polluted value — so Pattern 1 must not flag these as gadgets.
    called_member_locs: Set[Tuple[int, int]] = set()

    def collect_call_callees(node):
        if _node_type(node) == "CallExpression":
            callee = getattr(node, "callee", None)
            if callee is not None and _node_type(callee) == "MemberExpression":
                called_member_locs.add((_loc_line(callee), _loc_col(callee)))

    _walk(tree, collect_call_callees)

    def _emit_generic_eval_gadget(node, args_list, sink_label):
        """Emit gadget if args_list[0] is X.Y where Y is unowned-property pattern."""
        if not args_list:
            return
        arg = args_list[0]
        if _node_type(arg) != "MemberExpression":
            return
        if getattr(arg, "computed", False):
            return
        arg_prop = arg.property
        if _node_type(arg_prop) != "Identifier":
            return
        prop_name = arg_prop.name
        if prop_name in assigned_props:
            return
        if _receiver_is_dom_element(arg.object):
            return
        if prop_name in ("length", "toString", "valueOf",
                         "constructor", "prototype", "hasOwnProperty"):
            return
        loc_key = (_loc_line(node), _loc_col(node), prop_name)
        if loc_key in seen_locations:
            return
        seen_locations.add(loc_key)
        findings.append(PPGadget(
            file=source_name, line=_loc_line(node), col=_loc_col(node),
            property_name=prop_name,
            sink_kind=f"generic-eval-gadget ({sink_label})",
            severity="critical",
            confidence=0.7,
            snippet=_snippet_of(source_code, node),
        ))

    def visit(node):
        t = _node_type(node)

        # Pattern 1: known gadget property names (allowlist)
        if t == "MemberExpression":
            if getattr(node, "computed", False):
                return
            prop = node.property
            if _node_type(prop) != "Identifier":
                return
            name = prop.name
            if name not in _KNOWN_GADGET_PROPS:
                return
            # Own property assigned in THIS file → not prototype-inherited, so
            # not a pollution gadget (matches the guard in _emit_generic_eval_
            # gadget). Fixes FP on e.g. `cfg.tagNameCheck = /.../`.
            if name in assigned_props:
                return
            # Method invocation `X.name(...)` (e.g. DOMPurify.sanitize(x)) →
            # calling a real function, not reading a polluted value. Fixes FP
            # where calling a sanitizer/escaper was reported as a gadget.
            if (_loc_line(node), _loc_col(node)) in called_member_locs:
                return
            if name in ("innerHTML", "outerHTML", "documentWrite"):
                if _receiver_is_dom_element(node.object):
                    return
            sink_kind, severity = _KNOWN_GADGET_PROPS[name]
            loc_key = (_loc_line(node), _loc_col(node), name)
            if loc_key in seen_locations:
                return
            seen_locations.add(loc_key)
            findings.append(PPGadget(
                file=source_name, line=_loc_line(node), col=_loc_col(node),
                property_name=name, sink_kind=sink_kind,
                severity=severity, confidence=0.5,
                snippet=_snippet_of(source_code, node),
            ))
            return

        # Pattern 2: eval(X.Y) / Function(X.Y) / setTimeout(X.Y) / setInterval(X.Y)
        # where Y is not assigned anywhere in the file. The property read on an
        # unowned object inherits from prototype → exploitable when polluted.
        # PortSwigger lab pattern: eval(manager.sequence)
        if t == "CallExpression":
            callee = node.callee
            if callee is None:
                return
            ct = _node_type(callee)
            sink_label = None
            if ct == "Identifier":
                if callee.name in ("eval", "Function",
                                    "setTimeout", "setInterval"):
                    sink_label = f"{callee.name}(...)"
            elif ct == "MemberExpression":
                p = callee.property
                if (p is not None and _node_type(p) == "Identifier"
                        and p.name in ("eval", "Function",
                                        "setTimeout", "setInterval")):
                    sink_label = f"window.{p.name}(...)"
            if sink_label is not None:
                _emit_generic_eval_gadget(node, node.arguments or [], sink_label)
            return

        # Pattern 3: new Function(X.Y) — Function constructor
        if t == "NewExpression":
            callee = node.callee
            if callee is None:
                return
            if (_node_type(callee) == "Identifier"
                    and callee.name == "Function"):
                _emit_generic_eval_gadget(
                    node, node.arguments or [], "new Function(...)"
                )

    _walk(tree, visit)
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# DOMPURIFY VERSION DETECTION
# ──────────────────────────────────────────────────────────────────────────────

# Banner regex in DOMPurify source: /*! @license DOMPurify 3.2.1 ... */
_RE_DOMPURIFY_BANNER = re.compile(
    r"DOMPurify\s+([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE
)
# Version property assignment: VERSION = '3.2.1' or version: "3.2.1"
_RE_DOMPURIFY_VERSION_PROP = re.compile(
    r"\b(?:VERSION|version)\s*[:=]\s*['\"]([0-9]+\.[0-9]+\.[0-9]+)['\"]"
)
# DOMPurify identifier presence (signal it's loaded at all)
_RE_DOMPURIFY_PRESENT = re.compile(
    r"\bDOMPurify\b|\bdompurify\b"
)


def detect_dompurify_version(source_code: str) -> Optional[str]:
    """Try to extract DOMPurify version from JS source. Returns 'X.Y.Z' or None."""
    if not source_code:
        return None
    m = _RE_DOMPURIFY_BANNER.search(source_code)
    if m:
        return m.group(1)
    # Look near DOMPurify identifier for a version literal
    for vm in _RE_DOMPURIFY_VERSION_PROP.finditer(source_code):
        # Check if DOMPurify appears within +-300 chars
        idx = vm.start()
        nearby = source_code[max(0, idx - 300):idx + 300]
        if _RE_DOMPURIFY_PRESENT.search(nearby):
            return vm.group(1)
    return None


def classify_dompurify_version(ver: Optional[str]) -> Optional[str]:
    """Return 'vulnerable' / 'safe' / None.
    CVE-2026-41238: DOMPurify >=3.0.1, <3.4.0 is vulnerable."""
    if not ver:
        return None
    try:
        parts = [int(x) for x in ver.split(".")]
    except (ValueError, AttributeError):
        return None
    if len(parts) < 3:
        return None
    major, minor, patch = parts[0], parts[1], parts[2]
    # 3.0.1 ≤ ver < 3.4.0
    if major != 3:
        return "safe"
    # (v10.76: removed dead `if minor < 0` branch — minor is parsed from
    #  int(x) above, so it is always >= 0 and the branch never executed.)
    if minor == 0 and patch == 0:
        return "safe"   # 3.0.0 used Object.create(null), safe
    if minor < 4:
        return "vulnerable"
    return "safe"


def detect_dompurify_in_source(source_code: str,
                                source_name: str = "<inline>"
                                ) -> Optional[DOMPurifyDep]:
    """Scan JS for DOMPurify presence; if version detectable, classify.

    v10.10: Now uses data-driven CVE feed (_dompurify_cve_feed.py) instead
    of hardcoded version range. Single version may match MULTIPLE CVEs.
    """
    if not source_code:
        return None
    if not _RE_DOMPURIFY_PRESENT.search(source_code):
        return None
    ver = detect_dompurify_version(source_code)
    # v10.10: feed-based CVE matching (replaces classify_dompurify_version)
    matched: List[Dict] = []
    if ver:
        try:
            from _dompurify_cve_feed import match_cves_for_version
            matched = match_cves_for_version(ver)
        except ImportError:
            # Fallback to legacy logic if feed module missing
            cls = classify_dompurify_version(ver)
            if cls == "vulnerable":
                # Legacy: treat as CVE-2026-41238 only (preserve old behavior)
                matched = [{
                    "cve": "CVE-2026-41238",
                    "severity": "critical",
                    "vector": "prototype-pollution-bypass",
                    "description": "Legacy fallback (CVE feed unavailable)",
                    "bypass_payload": "",
                    "reference": "",
                }]
    return DOMPurifyDep(
        file=source_name,
        version=ver,
        line=0,
        is_vulnerable=bool(matched),  # backward compat: any CVE = vulnerable
        confidence=0.85 if ver else 0.4,
        matched_cves=matched,
    )


# ──────────────────────────────────────────────────────────────────────────────
# DYNAMIC PROBE — URL builders for client-side PP test
# ──────────────────────────────────────────────────────────────────────────────

def make_pp_probe_url(target_url: str, probe_token: str = "XSGS_PP_PROBE") -> str:
    """Build a URL that attempts client-side PP via __proto__ in query string.

    Strategy: append ?__proto__[<token>]=PWNED to the URL. If the application
    parses query string with a vulnerable parser (qs/extended, custom split),
    Object.prototype.<token> will be set after parsing.

    The actual detection (checking Object.prototype.<token> in DevTools) is
    done by DOM v6 fáze with appropriate hooks."""
    sep = "&" if "?" in target_url else "?"
    # Don't double-pollute if probe is already in URL
    if probe_token in target_url:
        return target_url
    return f"{target_url}{sep}__proto__[{probe_token}]=PWNED"


def make_pp_probe_payloads(probe_token: str = "XSGS_PP_PROBE"
                            ) -> List[Tuple[str, str]]:
    """Return list of (label, query_fragment) variants for PP probing.
    Different parsers handle different syntaxes."""
    return [
        ("dotted",     f"__proto__.{probe_token}=PWNED"),
        ("bracketed",  f"__proto__[{probe_token}]=PWNED"),
        ("constructor", f"constructor.prototype.{probe_token}=PWNED"),
        ("constructor-bracketed",
                       f"constructor[prototype][{probe_token}]=PWNED"),
    ]


# ──────────────────────────────────────────────────────────────────────────────
# COMBINED REPORT
# ──────────────────────────────────────────────────────────────────────────────

def build_pollution_report(url: str,
                            inline_scripts: Optional[List[str]] = None,
                            external_scripts: Optional[Dict[str, str]] = None
                            ) -> PPReport:
    """One-shot analysis: scan all scripts for PP sources, gadgets, DOMPurify."""
    report = PPReport(url=url)

    for body in (inline_scripts or []):
        report.sources.extend(
            detect_pollution_sources(body, url + "#inline")
        )
        report.gadgets.extend(
            detect_pollution_gadgets(body, url + "#inline")
        )
        dp = detect_dompurify_in_source(body, url + "#inline")
        if dp is not None:
            report.dompurify_deps.append(dp)

    for ext_url, src in (external_scripts or {}).items():
        report.sources.extend(detect_pollution_sources(src, ext_url))
        report.gadgets.extend(detect_pollution_gadgets(src, ext_url))
        dp = detect_dompurify_in_source(src, ext_url)
        if dp is not None:
            report.dompurify_deps.append(dp)

    return report
