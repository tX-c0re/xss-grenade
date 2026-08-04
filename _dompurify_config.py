"""
_dompurify_config.py — config-aware DOMPurify bypass detection (v10.70).

The version-based CVE feed (_dompurify_cve_feed.py) catches KNOWN bugs in
specific DOMPurify releases. But the dominant real-world DOMPurify bypass is not
a library bug at all — it's the APPLICATION weakening its own config. DOMPurify
is safe by default; developers routinely re-open holes:

    DOMPurify.sanitize(dirty, { ADD_TAGS: ['iframe'], ADD_ATTR: ['onload'] })
    DOMPurify.sanitize(dirty, { ALLOW_UNKNOWN_PROTOCOLS: true })   // javascript:
    DOMPurify.setConfig({ ADD_URI_SAFE_ATTR: ['href'] })          // no protocol check
    DOMPurify.sanitize(dirty, { USE_PROFILES: { svg: true } })    // mXSS surface

Each of those makes the sanitizer pass markup that then executes — no CVE, any
version. Classic scanners never look at the config object, so this is almost
entirely untooled.

This module statically audits the page's JS for DOMPurify `.sanitize(x, {…})`
and `.setConfig({…})` calls and flags dangerous option values. It is precise by
construction: the option NAMES (ADD_TAGS / ADD_ATTR / ALLOW_UNKNOWN_PROTOCOLS /
ADD_URI_SAFE_ATTR / USE_PROFILES / ADD_DATA_URI_TAGS) are DOMPurify-specific, and
we only report values that genuinely re-enable a dangerous vector.

Public API:
    analyze_dompurify_config(js_source, source_name="") -> List[Dict]
    scan_dompurify_config(body, page_url="") -> List[Dict]
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

try:
    import esprima
    _ESPRIMA_AVAILABLE = True
except Exception:
    _ESPRIMA_AVAILABLE = False
    esprima = None

# Only bother if the source actually uses DOMPurify — kills any wild FP.
_GATE = re.compile(r"DOMPurify|dompurify|(?<![\w.])purify\b|\.sanitize\s*\(",
                   re.IGNORECASE)

_RE_INLINE_SCRIPT = re.compile(r"<script\b[^>]*>(.*?)</script>",
                               re.IGNORECASE | re.DOTALL)

# tag -> (severity, why)
_DANGER_TAGS = {
    "script":  ("critical", "arbitrary JavaScript execution"),
    "iframe":  ("critical", "iframe src/srcdoc → JS or nested HTML injection"),
    "object":  ("high",     "object data → plugin / JS execution"),
    "embed":   ("high",     "embed src → plugin / JS execution"),
    "base":    ("high",     "base href hijacks every relative URL on the page"),
    "form":    ("high",     "form action/formaction → request forgery / UI redress"),
    "meta":    ("high",     "meta refresh redirect / http-equiv abuse"),
    "frame":   ("high",     "frame src → JS execution"),
    "frameset":("high",     "frameset → framed JS"),
    "link":    ("medium",   "link can pull external resources / preload"),
    "style":   ("medium",   "CSS injection / scriptless-exfil surface"),
    "svg":     ("medium",   "SVG namespace-confusion mXSS surface"),
    "math":    ("medium",   "MathML foreign-content mXSS surface"),
    "template":("medium",   "declarative shadow DOM smuggling surface"),
    "annotation-xml": ("medium", "MathML foreign content"),
    "portal":  ("medium",   "portal src"),
}
# non-event URI/danger attributes -> (severity, why)
_DANGER_ATTR = {
    "srcdoc":     ("high", "iframe srcdoc carries raw HTML → nested injection"),
    "xlink:href": ("high", "SVG xlink:href → javascript: / use-element abuse"),
    "action":     ("high", "form action target"),
    "formaction": ("high", "button/input formaction overrides the form target"),
    "href":       ("medium", "URI attribute (still protocol-filtered unless URI-safe)"),
    "src":        ("medium", "URI attribute"),
    "data":       ("medium", "object data URI"),
    "ping":       ("medium", "a ping beacon target"),
    "background": ("medium", "legacy background URI"),
    "poster":     ("low",  "video poster URI"),
}
_URI_ATTR = {"href", "src", "xlink:href", "srcdoc", "action", "formaction",
             "data", "ping", "background", "dynsrc", "lowsrc", "poster",
             "codebase", "cite"}
_DATA_URI_DANGER = {"iframe", "object", "embed", "a", "link", "script"}


def _mk(page_url: str, option: str, detail: str, sev: str, why: str) -> Dict:
    return {
        "url": page_url,
        "param": "(page DOMPurify config)",
        "payload": "%s: %s" % (option, detail),
        "context": "dompurify-config-%s" % option.lower(),
        "source": "dompurify-config",
        "severity": sev,
        "cwe_hint": "CWE-79",
        "option": option,
        "detail": detail,
        "evidence": "DOMPurify config sets %s including '%s' — %s." % (
            option, detail, why),
        "description": (
            "The application weakens its own DOMPurify configuration: %s '%s' "
            "re-enables a sanitizer-bypassing vector (%s). DOMPurify is safe by "
            "default; this holds on ANY version — no CVE required — and classic "
            "scanners never inspect the config object. Remove the option or "
            "restrict it (avoid ADD_TAGS/ADD_ATTR for active content, keep the "
            "default protocol allow-list)." % (option, detail, why)),
    }


def _as_str_list(v) -> List[str]:
    if isinstance(v, list):
        return [str(x) for x in v if isinstance(x, str) and x]
    if isinstance(v, str):
        return [s.strip().strip("'\"") for s in v.split(",") if s.strip()]
    return []


def _flag(config: Dict, page_url: str) -> List[Dict]:
    """Given a normalized config dict, return findings for dangerous options."""
    out: List[Dict] = []
    for t in _as_str_list(config.get("ADD_TAGS")):
        tl = t.lower()
        if tl in _DANGER_TAGS:
            sev, why = _DANGER_TAGS[tl]
            out.append(_mk(page_url, "ADD_TAGS", tl, sev, why))
    for a in _as_str_list(config.get("ADD_ATTR")):
        al = a.lower()
        if al.startswith("on") and len(al) > 2:
            out.append(_mk(page_url, "ADD_ATTR", al, "critical",
                           "event-handler attribute → inline JS execution"))
        elif al in _DANGER_ATTR:
            sev, why = _DANGER_ATTR[al]
            out.append(_mk(page_url, "ADD_ATTR", al, sev, why))
    for a in _as_str_list(config.get("ADD_URI_SAFE_ATTR")):
        al = a.lower()
        if al in _URI_ATTR:
            out.append(_mk(page_url, "ADD_URI_SAFE_ATTR", al, "high",
                           "marks a URI attribute URI-safe → skips protocol "
                           "filter → javascript:/data: URIs allowed"))
    if config.get("ALLOW_UNKNOWN_PROTOCOLS") is True:
        out.append(_mk(page_url, "ALLOW_UNKNOWN_PROTOCOLS", "true", "critical",
                       "disables the protocol allow-list → javascript:/data: "
                       "URIs pass through"))
    up = config.get("USE_PROFILES")
    if isinstance(up, dict):
        if up.get("svg") is True:
            out.append(_mk(page_url, "USE_PROFILES", "svg", "medium",
                           "enables SVG → namespace-confusion mXSS surface"))
        if up.get("mathMl") is True or up.get("mathml") is True:
            out.append(_mk(page_url, "USE_PROFILES", "mathMl", "medium",
                           "enables MathML → foreign-content mXSS surface"))
    for t in _as_str_list(config.get("ADD_DATA_URI_TAGS")):
        tl = t.lower()
        if tl in _DATA_URI_DANGER:
            out.append(_mk(page_url, "ADD_DATA_URI_TAGS", tl, "high",
                           "data: URI allowed on <%s> → HTML/JS smuggling" % tl))
    if config.get("WHOLE_DOCUMENT") is True:
        out.append(_mk(page_url, "WHOLE_DOCUMENT", "true", "low",
                       "sanitizes the whole document → wider tag surface "
                       "(html/head/body/meta)"))
    return out


# ── AST extraction (esprima) ─────────────────────────────────────────────────

def _key_name(k) -> Optional[str]:
    t = getattr(k, "type", None)
    if t == "Identifier":
        return getattr(k, "name", None)
    if t == "Literal":
        val = getattr(k, "value", None)
        return str(val) if val is not None else None
    return None


def _value(v):
    t = getattr(v, "type", None)
    if t == "ArrayExpression":
        return [_value(e) for e in (getattr(v, "elements", None) or [])]
    if t == "Literal":
        return getattr(v, "value", None)
    if t == "ObjectExpression":
        return _obj_to_dict(v)
    if t == "UnaryExpression" and getattr(v, "operator", None) == "!":
        arg = _value(getattr(v, "argument", None))
        if arg == 0:
            return True   # !0 (minified true)
        if arg == 1:
            return False  # !1 (minified false)
    return None


def _obj_to_dict(node) -> Dict:
    out: Dict = {}
    for prop in (getattr(node, "properties", None) or []):
        if getattr(prop, "type", None) != "Property":
            continue
        k = _key_name(getattr(prop, "key", None))
        if k is None:
            continue
        out[k] = _value(getattr(prop, "value", None))
    return out


def _ast_configs(js: str) -> List[Dict]:
    """Every ObjectExpression passed as a DOMPurify sanitize/setConfig config."""
    configs: List[Dict] = []
    try:
        tree = esprima.parseScript(js, options={"tolerant": True})
    except Exception:
        try:
            tree = esprima.parseModule(js, options={"tolerant": True})
        except Exception:
            return configs

    def visit(node):
        if getattr(node, "type", None) != "CallExpression":
            return
        callee = getattr(node, "callee", None)
        if getattr(callee, "type", None) != "MemberExpression":
            return
        prop = getattr(callee, "property", None)
        pname = getattr(prop, "name", None)
        args = getattr(node, "arguments", None) or []
        cfg_node = None
        if pname == "sanitize" and len(args) >= 2:
            cfg_node = args[1]
        elif pname == "setConfig" and len(args) >= 1:
            cfg_node = args[0]
        if cfg_node is not None and getattr(cfg_node, "type", None) == "ObjectExpression":
            configs.append(_obj_to_dict(cfg_node))

    def _walk(n, depth=0):
        if depth > 300 or not hasattr(n, "type"):
            return
        visit(n)
        for attr in dir(n):
            if attr.startswith("_") or attr in (
                    "type", "loc", "range", "name", "value", "raw", "kind",
                    "operator", "computed", "shorthand", "method", "prefix",
                    "delegate", "async", "generator", "static", "directive"):
                continue
            try:
                v = getattr(n, attr)
            except Exception:
                continue
            if isinstance(v, list):
                for it in v:
                    _walk(it, depth + 1)
            elif hasattr(v, "type"):
                _walk(v, depth + 1)

    try:
        _walk(tree)
    except RecursionError:
        pass
    return configs


# ── regex fallback (also catches var-defined / esprima-unparseable configs) ──

def _split(s: str) -> List[str]:
    return [x.strip().strip("'\"") for x in s.split(",") if x.strip()]


def _regex_config(js: str) -> Dict:
    cfg: Dict = {}
    for key in ("ADD_TAGS", "ADD_ATTR", "ADD_URI_SAFE_ATTR", "ADD_DATA_URI_TAGS"):
        m = re.search(key + r"\s*:\s*\[([^\]]*)\]", js)
        if m:
            cfg[key] = _split(m.group(1))
    if re.search(r"ALLOW_UNKNOWN_PROTOCOLS\s*:\s*(?:true|!0|1)\b", js):
        cfg["ALLOW_UNKNOWN_PROTOCOLS"] = True
    if re.search(r"WHOLE_DOCUMENT\s*:\s*(?:true|!0|1)\b", js):
        cfg["WHOLE_DOCUMENT"] = True
    m = re.search(r"USE_PROFILES\s*:\s*\{([^}]*)\}", js)
    if m:
        inner = m.group(1)
        up: Dict = {}
        if re.search(r"\bsvg\s*:\s*(?:true|!0|1)\b", inner):
            up["svg"] = True
        if re.search(r"\bmathMl\s*:\s*(?:true|!0|1)\b", inner, re.IGNORECASE):
            up["mathMl"] = True
        if up:
            cfg["USE_PROFILES"] = up
    return cfg


def analyze_dompurify_config(js_source: str, source_name: str = "") -> List[Dict]:
    """Audit one JS source for dangerous DOMPurify configuration. Returns
    engine-standard findings (deduped by option+detail)."""
    if not js_source or not _GATE.search(js_source):
        return []
    configs: List[Dict] = []
    if _ESPRIMA_AVAILABLE:
        configs.extend(_ast_configs(js_source))
    configs.append(_regex_config(js_source))  # always — catches minified/var-defined
    findings: List[Dict] = []
    seen = set()
    for cfg in configs:
        for f in _flag(cfg, source_name):
            k = (f["option"], f["detail"])
            if k not in seen:
                seen.add(k)
                findings.append(f)
    return findings


def scan_dompurify_config(body: str, page_url: str = "") -> List[Dict]:
    """Scan a page's inline <script> blocks for dangerous DOMPurify config."""
    if not body:
        return []
    findings: List[Dict] = []
    seen = set()
    for m in _RE_INLINE_SCRIPT.finditer(body):
        js = m.group(1)
        if not js or not js.strip():
            continue
        for f in analyze_dompurify_config(js, page_url):
            k = (f["option"], f["detail"])
            if k not in seen:
                seen.add(k)
                findings.append(f)
    return findings
