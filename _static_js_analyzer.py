"""
_static_js_analyzer.py
======================
Static JavaScript analyzer for DOM XSS — taint flow tracking through AST.

Background
----------
Existing detection (DOM v6) requires running JS in a real browser to find
source→sink chains. That is the ground truth, but it has costs:
  - ~1-2s per page (headless Chromium)
  - Cannot scan external JS files that aren't loaded by the target page
  - Misses chains that only execute behind authentication or specific
    user actions
  - Wastes time on pages where JS files don't even contain dangerous
    sources (most of them)

Static JS analysis fills the gap. Read the source, parse to AST, track
which variables hold tainted data (originated from a SOURCE), check if
any tainted variable reaches a SINK. This finds:
  - DOM XSS in code that hasn't even been loaded yet (linked .js files)
  - DOM XSS in code paths that headless wouldn't trigger
  - Pre-emptive findings before active scanning runs

This is NOT a replacement for DOM v6 — it's complementary:
  - Static finds candidates fast (~ms per file)
  - DOM v6 confirms exec at runtime (with canary in actual sink)
  - Headless verifier confirms exec produces dialog

Scope
-----
We track taint at variable-level. We do NOT model:
  - Object property assignment (foo.bar = tainted) — would need points-to
  - Function returns (function f(x) { return x.bad() })
  - Cross-file flows (taint across <script> boundaries)

We DO model:
  - Variable declarations: var a = source
  - Assignments: a = source.member; b = a.method(arg)
  - Member access on tainted: a = location.hash; b = a.slice(1)
  - Function calls with tainted args: atob(tainted), eval(tainted)
  - Sink writes: x.innerHTML = tainted, eval(tainted), document.write(tainted)

Public API
----------

    analyze_js_source(source_code, source_name="<inline>") -> List[StaticFinding]
        Parse source code and return all source→sink chains found.

    analyze_html_inline_scripts(html, page_url="") -> List[StaticFinding]
        Extract all <script> tags' contents and analyze each.

    StaticFinding
        .source_name      e.g. "location.hash"
        .sink_name        e.g. "innerHTML"
        .chain            list of (operation, line_no) tuples
        .severity         "high" / "medium" / "low"
        .confidence       0.0 – 1.0
        .file             source name
        .line             line where sink fires
        .col              column where sink fires
        .snippet          ~100 chars of code around the sink
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger("xss_grenade.static_js")

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
class StaticFinding:
    """A confirmed source→sink chain in static JS code."""
    source_name: str          # e.g. "location.hash"
    sink_name: str            # e.g. "innerHTML"
    chain: List[Tuple[str, int]] = field(default_factory=list)
    # ↑ list of (operation_label, line_no) — chain[0] is source, chain[-1] is sink
    severity: str = "medium"  # "high"/"medium"/"low"
    confidence: float = 0.7
    file: str = ""            # source name (URL or "<inline>")
    line: int = 0             # line where sink fires
    col: int = 0
    snippet: str = ""         # ~100 chars around sink
    # v10.86: how much of the value reaching the sink the attacker can set —
    # "full" | "prefixed" (whole URL, origin not stripped) | "none".
    controllability: str = "full"

    def __repr__(self) -> str:
        return (f"StaticFinding({self.source_name} → {self.sink_name} "
                f"@ {self.file}:{self.line} sev={self.severity})")


# ──────────────────────────────────────────────────────────────────────────────
# SOURCE / SINK DEFINITIONS
# ──────────────────────────────────────────────────────────────────────────────
#
# Sources: expressions that introduce attacker-controlled data into the page.
# Each source is a tuple describing how to recognize it as a MemberExpression
# (or CallExpression).
#
# Format: ("Object.path", "kind") where kind ∈ {"member", "call", "newcall"}.
# We recognize them in AST node types:
#   - MemberExpression with .object.name = X and .property.name = Y → "X.Y"
#   - CallExpression with callee a MemberExpression matching above → "X.Y(...)"

# Tier 1 — direct URL/storage sources
_SOURCES_MEMBER = {
    # Format: (object, property) → label
    ("location", "href"):        "location.href",
    ("location", "search"):      "location.search",
    ("location", "hash"):        "location.hash",
    ("location", "pathname"):    "location.pathname",
    ("document", "URL"):         "document.URL",
    ("document", "documentURI"): "document.documentURI",
    ("document", "referrer"):    "document.referrer",
    ("document", "cookie"):      "document.cookie",
    ("window", "name"):          "window.name",
    ("self", "name"):            "self.name",
    # ── v10.14: moderní browser API sources ──
    # location.origin/host/hostname — využíváno v origin checking které
    # může být obejito (URL spoofing přes uživatelské info)
    ("location", "origin"):      "location.origin",
    ("location", "host"):        "location.host",
    ("location", "hostname"):    "location.hostname",
    # history API — historicky podceňované source
    ("history", "state"):        "history.state",
    # document.location (alias) — někteří devs to píšou takto
    ("document", "location"):    "document.location",
    # ── v10.14: window.location.X varianty ──
    # _member_path() flattnuje window.location.href na ("window.location", "href"),
    # takže musíme mít explicitní klíče s tečkou v object name. Bez nich
    # devs píšící `window.location.hash` mají XSS source nedetekován.
    ("window.location", "href"):     "window.location.href",
    ("window.location", "search"):   "window.location.search",
    ("window.location", "hash"):     "window.location.hash",
    ("window.location", "pathname"): "window.location.pathname",
    ("window.location", "origin"):   "window.location.origin",
    ("window.location", "host"):     "window.location.host",
    # document.location.X varianty (alias)
    ("document.location", "href"):     "document.location.href",
    ("document.location", "search"):   "document.location.search",
    ("document.location", "hash"):     "document.location.hash",
}

# v10.82 DEPTH: XMLHttpRequest response is a classic taint source, but the
# receiver name varies (xhr / req / this.xhr / x), so it can't be keyed on a fixed
# object. Match by PROPERTY name alone — these names are XHR-specific (fetch uses
# .text()/.json(), axios uses .data), so a bare property match is FP-safe.
_XHR_RESPONSE_PROPS = {"responseText", "responseXML"}

# ── v10.86: source CONTROLLABILITY ───────────────────────────────────────────
# Not every URL source hands the attacker the same power, and treating them
# alike was measured (Firing Range benchmark) as 64 false positives — 60% of the
# safe DOM corpus, reported at high/critical.
#
# A WHOLE-URL source returns `scheme://host/path?query#frag`. The attacker
# cannot remove the origin prefix, so handing that value STRAIGHT to a sink is
# not exploitable:
#     eval(document.URL)            -> SyntaxError; the URL is not valid JS
#     el.innerHTML = document.URL   -> inert text; browsers %-encode < and >
#                                      in the query and fragment
# The same source becomes genuinely dangerous the moment the code EXTRACTS from
# it (`.split('#')[1]`, `.substring(i)`, a URLSearchParams lookup) — which is
# exactly what `location.hash.substr(1)` does implicitly. So the discriminator
# is not the source name, it is whether an extraction happened on the way.
_WHOLE_URL_SOURCE_LABELS = {
    "location.href", "window.location.href", "document.location.href",
    "document.URL", "document.URLUnencoded", "document.documentURI",
    "document.baseURI", "document.location", "location", "window.location",
}

# Weaker still: on a fixed server route the attacker controls none of these.
# `location.pathname` was 12 of the 64 measured false positives.
_UNCONTROLLED_SOURCE_LABELS = {
    "location.pathname", "window.location.pathname",
    "location.origin", "window.location.origin",
    "location.host", "window.location.host",
    "location.hostname", "window.location.hostname",
}

# Operations that can strip the fixed origin prefix off a whole-URL value and
# hand the attacker's own slice to the sink. Deliberately NOT included:
# decodeURIComponent/decodeURI — they un-escape but do not remove the prefix, so
# `eval(decodeURIComponent(document.URL))` is still a SyntaxError.
_EXTRACTION_METHODS = {
    "substr", "substring", "slice", "split", "match", "exec",
    "replace", "replaceAll", "charAt", "at", "pop", "shift",
    "get", "getAll",
}

CONTROL_FULL = "full"            # attacker controls the value outright
CONTROL_PREFIXED = "prefixed"    # value carries an origin prefix, no extraction
CONTROL_NONE = "none"            # attacker controls nothing (fixed route/host)


def classify_controllability(source_label: str, extracted: bool) -> str:
    """How much of the value flowing into the sink can an attacker actually set?"""
    if source_label in _UNCONTROLLED_SOURCE_LABELS:
        return CONTROL_NONE
    if source_label in _WHOLE_URL_SOURCE_LABELS and not extracted:
        return CONTROL_PREFIXED
    return CONTROL_FULL

# Standalone identifiers when used in member access on `window` or globally
_SOURCES_GLOBAL = {
    "location", "document",   # not themselves sources but parents
}

# Tier 2 — call-style sources (must match callee pattern)
# Format: (object, method) → label
_SOURCES_CALL = {
    ("URLSearchParams.prototype", "get"): "URLSearchParams.get",
    ("localStorage", "getItem"):          "localStorage.getItem",
    ("sessionStorage", "getItem"):        "sessionStorage.getItem",
    # ── v10.14: moderní call-style sources ──
    # URLSearchParams: getAll() vrací array, get() jeden — oboje source
    ("URLSearchParams.prototype", "getAll"): "URLSearchParams.getAll",
    # URL.searchParams.get — moderní browser pattern (URL constructor)
    ("URL.prototype", "searchParams"):    "URL.searchParams",
    # IndexedDB
    ("IDBObjectStore.prototype", "get"):  "IndexedDB.get",
    # FormData (form submissions)
    ("FormData.prototype", "get"):        "FormData.get",
    ("FormData.prototype", "getAll"):     "FormData.getAll",
    # Cache API (Service Workers)
    ("Cache.prototype", "match"):         "Cache.match",
    # Note: we also match these when called on any instance (heuristic)
}

# v10.76 FP fix: a `.get()`/`.getAll()` is only a URL source when its RECEIVER
# is a URLSearchParams (or URL().searchParams / a name-hinted params var). Bare
# Map/WeakMap/Immutable/Redux/config/ORM `.get()` and jQuery `$(x).get(0)` must
# NOT be treated as tainted — that was a massive false-positive source.
_URLPARAM_NAME_RX = re.compile(r"(?:param|search|query|\bqs\b|urlparam)", re.I)


def _is_urlsearchparams_like(obj) -> bool:
    if obj is None:
        return False
    nt = _node_type(obj)
    if nt == "NewExpression":                       # new URLSearchParams(...)
        c = getattr(obj, "callee", None)
        return (_node_type(c) == "Identifier"
                and getattr(c, "name", "") == "URLSearchParams")
    if nt == "MemberExpression":                    # url.searchParams / new URL(x).searchParams
        p = getattr(obj, "property", None)
        return (not getattr(obj, "computed", False)
                and _node_type(p) == "Identifier"
                and getattr(p, "name", "") == "searchParams")
    if nt == "Identifier":                          # urlParams / searchParams / query / qs …
        return bool(_URLPARAM_NAME_RX.search(getattr(obj, "name", "") or ""))
    return False

# v10.14: postMessage / Broadcast / Worker message-event sources
# Tyto jsou speciální: source je property `data` na události typu
# MessageEvent. Statický analyzátor je matchne podle identifier name
# `data` v handleru registrovaném pro "message" event — viz
# _MESSAGE_EVENT_DATA_PROPS níže. (Detekce běží separátně v
# _detect_message_event_source(), ne přes _SOURCES_MEMBER, protože
# vyžaduje context awareness — že identifier patří k MessageEvent handleru.)
_MESSAGE_EVENT_DATA_PROPS = {
    "data":   "MessageEvent.data",
    "origin": "MessageEvent.origin",
    "source": "MessageEvent.source",
}

# Identifier-only callees we treat as sources/intermediates
_INTERMEDIATE_FUNCS = {
    "atob", "decodeURIComponent", "decodeURI", "unescape",
    "JSON.parse",  # special — handled in member-call lookup
    # v10.14: další běžně používané přechodové funkce
    "decodeURI", "decodeURIComponent",
}

# Sinks — assignment LHS or call callee
# Format: (object_pattern, property) → (label, severity)
# object_pattern can be:
#   - a string — strict match
#   - "*" — any object
_SINKS_ASSIGN = {
    # property → (label, severity)
    "innerHTML":              ("innerHTML",       "high"),
    "outerHTML":              ("outerHTML",       "high"),
    # ── v10.14: moderní HTML injection sinks (assignment forma) ──
    # srcdoc na iframe — `iframe.srcdoc = tainted` = full HTML inject
    "srcdoc":                 ("iframe.srcdoc",   "high"),
    # v10.76 FP fix: `action`/`formAction`/`data` REMOVED — they match by bare
    # property name irrespective of the LHS object, so `component.data = api`,
    # `store.action = x`, `chart.data = tainted` all emitted a medium finding.
    # These generic property names produced far more false positives than the
    # rare `form.action = "javascript:…"` / `object.data = "javascript:…"` they
    # were meant to catch, so they are dropped (net FP reduction).
    # ── v10.14 doplneni: URL property assignments ──
    # a.href = tainted, area.href = tainted — tainted URL může mít
    # javascript: scheme. Medium severity (vyžaduje user click).
    "href":                   ("anchor.href",     "medium"),
    # img.src / iframe.src / script.src = tainted (script je critical
    # protože automaticky executuje)
    "src":                    ("element.src",     "medium"),
    # cite na blockquote/q/del/ins — méně častý ale platný
    # (omitted — moc generický identifier "cite", false-positive risk)
    # v10.14b: style.cssText = tainted — CSS injection
    # (IE expression(), url(javascript:)) — medium severity
    "cssText":                ("style.cssText",     "medium"),
    # Don't include `value`, `textContent` — those are not exec sinks
}

# ── Taint terminators ─────────────────────────────────────────────────────────
# Funkce volané na tainted hodnotě, které ji sanitizují nebo encodují.
# Pokud je tainted value wrappovaná v některé z těchto funkcí, taint flow
# se ZASTAVÍ — nepropaguje se dál.
#
# Příklady:
#   var safe = encodeURIComponent(location.hash);  → safe NIE JE tainted
#   var safe = DOMPurify.sanitize(x);              → safe NIE JE tainted
#   var safe = escapeHtml(x);                      → safe NIE JE tainted
#
# POZOR: `replace(/x/g, '')` — jen pokud pattern je dostatečně agresivní
#         (odstraňuje < > nebo tagy). Simple replace nemusí stačit.
#         Tu detekujeme jako "maybe-sanitized" = MEDIUM místo HIGH/CRIT.
_TAINT_TERMINATORS_GLOBAL = {
    # URL encoding
    "encodeURIComponent", "encodeURI",
    # DOM escaping / HTML encoding
    "escapeHtml", "htmlEscape", "htmlEncode", "escapeHTML", "escapeXml",
    # DOMPurify, sanitize-html, xss-clean — popular sanitizer libraries
    # Detekované jako `DOMPurify.sanitize(x)` přes member — viz
    # _TAINT_TERMINATORS_MEMBER níže. Ale některé projekty volají
    # `sanitize(x)` jako global alias.
    "sanitize", "purify",
    # v10.82 DEPTH: numeric coercion — a number/boolean can never carry HTML/JS
    # markup, so parseInt(location.hash) etc. is NOT a string-injection source.
    # Terminating here removes over-taint FPs (the any-tainted-arg rule would
    # otherwise propagate) without hiding any real string-context injection.
    "parseInt", "parseFloat", "Number", "isNaN", "isFinite", "BigInt",
    # JSON.stringify encoduje nebezpečné znaky v string kontextu
    "JSON.stringify",
    # btoa / atob — encoding (nesnižuje severity na 0, ale propaguje
    # jako ENCODED — taint stále existuje ale je méně přímočarý)
    # Zahrneme jako partial terminator: snížíme severity o 1 stupeň.
    # "btoa", "atob",  # záměrně vynecháno — jen encode, lze reverzovat
    # CSP nonce injection — nonce je safe inject
    # "createNonce",  # příliš projekt-specifické
}

_TAINT_TERMINATORS_MEMBER = {
    # DOMPurify.sanitize — nejpopulárnější sanitizer knihovna
    ("DOMPurify", "sanitize"),
    ("dompurify", "sanitize"),
    # sanitize-html
    ("sanitizeHtml", None),
    # Angular pipes — | safe, | sanitize
    # (nelze snadno detekovat v JS AST — jsou v template)
    # marked (markdown) — bezpečný výstup pokud sanitize=true
    # (příliš kontextové)
    # Google Closure escaping
    ("goog", "string.htmlEscape"),
    ("Sanitizer", "sanitize"),  # Web Sanitizer API
}

_SINKS_CALL_GLOBAL = {
    # callee identifier → (label, severity)
    "eval":          ("eval",          "critical"),
    "Function":      ("Function",      "critical"),
    "setTimeout":    ("setTimeout",    "high"),    # only string arg
    "setInterval":   ("setInterval",   "high"),    # only string arg
    "unsafeHTML":    ("Lit.unsafeHTML", "high"),
    "execScript":    ("execScript",    "critical"),
    "importScripts": ("importScripts", "critical"),
    "open":          ("window.open",   "medium"),

    # v10.14b: new sinks
    # new Worker(taintedUrl) — pokud URL je attacker-controlled, může
    # načíst arbitrary JS v Worker context.
    "Worker":        ("Worker(url)",   "high"),
    # SharedWorker — stejný attack vector
    "SharedWorker":  ("SharedWorker(url)", "high"),
}

# Member-call sinks: ("any", method) — method name matches any object
_SINKS_CALL_MEMBER = {
    # property → (label, severity, requires_object_pattern)
    "write":              ("document.write",          "high"),
    "writeln":            ("document.writeln",        "high"),
    "insertAdjacentHTML": ("insertAdjacentHTML",      "high"),
    # ── v10.14: moderní member-call HTML injection sinks ──
    # setHTMLUnsafe — 2024+ standard, opt-out z sanitization u Element
    "setHTMLUnsafe":      ("Element.setHTMLUnsafe",   "high"),
    # parseHTMLUnsafe — Document API 2024+
    "parseHTMLUnsafe":    ("Document.parseHTMLUnsafe","high"),
    # Range.createContextualFragment — old but XSS sink
    "createContextualFragment": ("Range.createContextualFragment", "high"),
    # DOMParser.parseFromString s "text/html" — parsing tainted HTML
    "parseFromString":    ("DOMParser.parseFromString","medium"),
    # jQuery $.parseHTML — explicitní HTML parsing
    "parseHTML":          ("jQuery.parseHTML",        "high"),
    # v10.14: window.open(tainted) — když tainted obsahuje javascript:
    # scheme, je to XSS. Stejný sink jako global open(), jen přes
    # member access (window.open).
    "open":               ("window.open",             "medium"),
    # postMessage(sensitiveData, "*") — info-leak.
    # Detekuje se zvlášť v check_sink (potřebuje zkontrolovat 2. argument).
    # Tento placeholder slouží jako reminder — actual detection je inline.

    # v10.14: indirect eval/Function via member access — bypass attempts
    # window.eval(x), globalThis.eval(x), self.eval(x) — same as direct
    # eval ale skrz member access. WAF bypass technique.
    "eval":               ("indirect eval (member)",  "critical"),
    "Function":           ("indirect Function (member)", "critical"),
    # v10.76 FP fix: `text`/`innerText` REMOVED from member-call sinks —
    # jQuery `$(x).text(v)` is the SAFE escaping setter and `resp.text()` is a
    # Response method; neither executes HTML. (script.text is handled only as a
    # property-assignment sink.) unsafeHTML + bypassSecurityTrust* also REMOVED
    # here — they live in _SINKS_ANGULAR_BYPASS (emitted at check_sink), and
    # having them in BOTH tables emitted every finding TWICE (duplicate bug).

    # v10.14b: additional member-call sinks
    "cssText":       ("style.cssText",          "medium"),  # CSS injection
    "execScript":    ("window.execScript",      "critical"),  # IE eval
    "trustAsHtml":   ("$sce.trustAsHtml",       "critical"),  # Angular SCE
    "trustAsJs":     ("$sce.trustAsJs",         "critical"),
    "trustAsUrl":    ("$sce.trustAsUrl",        "high"),
    "load":          ("jQuery.load(url)",       "high"),   # AJAX URL inject
    "Worker":        ("Worker(url)",            "high"),   # Worker src inject
}

# Special sink: location/href assignment with javascript: scheme
# Detected separately because we need to inspect the assigned VALUE.

# Property names for $.html(), $().html() jQuery-style sinks
_SINKS_JQUERY_LIKE = {
    "html":     ("jQuery.html()",     "high"),
    # v10.76 FP fix: append/prepend/after/before/replaceWith REMOVED. These are
    # also native DOM methods (ParentNode.append / ChildNode.after / …) that
    # insert their string argument as a TEXT node — they do NOT parse HTML. We
    # cannot tell a jQuery object from a DOM node statically, and native usage is
    # now the common case, so bare `.append(str)` was a false-positive source.
    # Only `.html()` is unambiguously the jQuery HTML setter.
}

# ── Framework escape-hatch sinks (v8 — 2026 SPA detection) ────────────────────
# Modern React/Vue/Angular/Svelte applications mostly use safe defaults, but
# every framework provides escape hatches that bypass the auto-escaping.
# These are the #1 source of XSS in modern SPAs (per HackerOne 2025 reports).

# React: JSX `dangerouslySetInnerHTML={{__html: x}}` compiles to
#   React.createElement(tag, { dangerouslySetInnerHTML: { __html: x } }, ...)
# We detect the object property "dangerouslySetInnerHTML" in any object
# expression — its presence with a tainted __html value is the bug.
_SINKS_FRAMEWORK_PROP = {
    "dangerouslySetInnerHTML": ("React.dangerouslySetInnerHTML", "high"),
    # v10.14: Vue 3 createElementBlock / Vue 2 render-fn domProps /
    # Solid.js createComponent props — všechny dávají do object literalu
    # property "innerHTML" s tainted hodnotou. Pure property check
    # (taint flow contralt nedaleko) — žádná nová větev logiky.
    # Pozor: tohle se matchne JEN když analyzer najde object literal
    # s vlastností "innerHTML" jako klíčem; statické přiřazení
    # ({innerHTML:"static text"}) projde dál bez findingu, protože
    # detect_source() nenajde tainted source.
    "innerHTML":               ("framework.innerHTML prop",    "high"),
    # Vue 2/3 explicit innerHTML přes domProps wrapper
    "domProps":                ("Vue.domProps",                "medium"),
}

# Angular DomSanitizer methods. Called on a sanitizer instance. We match by
# method name regardless of receiver — Angular minifies receiver names but
# preserves method names due to dependency injection metadata.
_SINKS_ANGULAR_BYPASS = {
    "bypassSecurityTrustHtml":        ("Angular.bypassSecurityTrustHtml",        "high"),
    "bypassSecurityTrustScript":      ("Angular.bypassSecurityTrustScript",      "critical"),
    "bypassSecurityTrustStyle":       ("Angular.bypassSecurityTrustStyle",       "medium"),
    "bypassSecurityTrustUrl":         ("Angular.bypassSecurityTrustUrl",         "high"),
    "bypassSecurityTrustResourceUrl": ("Angular.bypassSecurityTrustResourceUrl", "high"),
    # v10.14: Lit/Polymer unsafeHTML directive — `html\`...${unsafeHTML(x)}\``
    # Volá se jako globální funkce (po importu z lit/directives/unsafe-html).
    # Mírnější severity — Lit směřuje uživatele k tomu, vědomě označit
    # nebezpečné místo, takže výskyt unsafeHTML s tainted argumentem je
    # red flag, ale ne vždy exploit.
    "unsafeHTML":                     ("Lit.unsafeHTML",                          "high"),
    # POZNÁMKA: Mithril `m.trust(x)` byl zvažován, ale identifier `trust`
    # je v JS ekosystému příliš obecný (jakýkoli `lib.trust(x)` by se
    # matchnul jako Mithril). False-positive risk vyšší než hodnota.
    # Pokud je potřeba, lze přidat AST-level check na `m.trust()` s
    # ověřením receiveru = `m` a importem `mithril` — to je ale nová
    # kontrolní větev, ne data, takže to není v rozsahu této opravy.
}

# Svelte runtime helper for {@html} blocks. Name varies by Svelte version:
#   Svelte 3-4: `set_data()`/`html_tag` from internal runtime
#   Svelte 5: `$.html()` rune-based output
# We match by characteristic identifier patterns.
_SINKS_SVELTE_HTML = {
    "html_tag":  ("Svelte.{@html}",   "high"),   # Svelte 3-4 runtime helper
    "@html":     ("Svelte.{@html}",   "high"),   # rare standalone
}


# ──────────────────────────────────────────────────────────────────────────────
# AST HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _node_type(node) -> str:
    return getattr(node, "type", "") or ""


def _safe_type(node) -> str:
    """Type of an AST node, '' if node is None/typeless. Alias used by the
    predicate-taint helpers (v10.18)."""
    return getattr(node, "type", "") or "" if node is not None else ""


def _is_literal(node) -> bool:
    """True if node is a Literal (string/number/bool) — used to detect
    equality-narrowing  x === 'const'  in ternary predicates."""
    if node is None:
        return False
    nt = getattr(node, "type", "")
    if nt == "Literal":
        return True
    # esprima may represent template literals with no expressions as constants
    if nt == "TemplateLiteral" and not (getattr(node, "expressions", None) or []):
        return True
    return False


def _get_loc_line(node) -> int:
    try:
        return node.loc.start.line
    except (AttributeError, TypeError):
        return 0


def _handler_checks_origin(handler_fn, param_name: str):
    """v10.16: Zjistí, jestli a JAK message handler validuje event.origin.

    Vrací tuple (checks_origin: bool, weak: bool):
      - checks_origin=False → origin se vůbec nečte → MISSING (high-value bug)
      - checks_origin=True, weak=True → origin se čte, ale slabě
        (indexOf/includes/startsWith/endsWith/match bez striktní rovnosti) →
        bypassovatelné (např. e.origin.indexOf("trusted.com")!==-1 obejde
        "trusted.com.attacker.com"). STÁLE reportovatelný bug.
      - checks_origin=True, weak=False → striktní porovnání (===, !==, ==)
        nebo allow-list .test()/regex s kotvou → považujeme za OK.

    Slabá validace je častý high-payout nález — vypadá bezpečně, ale jde
    obejít. Proto ji odlišujeme od striktní.
    """
    if handler_fn is None or not param_name:
        return (False, False)
    state = {"reads_origin": False, "strict_cmp": False, "weak_cmp": False}

    # Slabé metody volané NA origin hodnotě
    _WEAK_METHODS = {"indexOf", "includes", "startsWith", "endsWith",
                     "search", "lastIndexOf"}

    def _is_param_origin(n):
        return (n is not None and _node_type(n) == "MemberExpression"
                and _node_type(getattr(n, "object", None)) == "Identifier"
                and getattr(n.object, "name", None) == param_name
                and _node_type(getattr(n, "property", None)) == "Identifier"
                and getattr(n.property, "name", None) == "origin")

    def _visit(node, depth=0):
        if depth > 200 or node is None:
            return
        nt = _node_type(node)
        # Striktní porovnání: e.origin === "..." / "..." === e.origin / !==/==
        if nt == "BinaryExpression" and getattr(node, "operator", "") in (
                "===", "!==", "==", "!="):
            if _is_param_origin(getattr(node, "left", None)) or \
               _is_param_origin(getattr(node, "right", None)):
                state["reads_origin"] = True
                state["strict_cmp"] = True
        # Slabé volání: e.origin.indexOf(...) / .includes(...) / .startsWith(...)
        if nt == "CallExpression":
            callee = getattr(node, "callee", None)
            if (callee is not None and _node_type(callee) == "MemberExpression"
                    and _node_type(getattr(callee, "property", None)) == "Identifier"):
                method = getattr(callee.property, "name", "")
                obj = getattr(callee, "object", None)
                if _is_param_origin(obj) and method in _WEAK_METHODS:
                    state["reads_origin"] = True
                    state["weak_cmp"] = True
                # .match() / .test() — regex; bez kotvy ^...$ je slabé,
                # ale staticky to nerozhodneme → konzervativně weak.
                if _is_param_origin(obj) and method in ("match",):
                    state["reads_origin"] = True
                    state["weak_cmp"] = True
        # Jakékoli čtení e.origin (i mimo porovnání) — aspoň reads_origin
        if _is_param_origin(node):
            state["reads_origin"] = True
        for attr in ("body", "consequent", "alternate", "test", "left",
                     "right", "argument", "arguments", "expression",
                     "callee", "object", "property", "init", "declarations",
                     "expressions", "elements", "value", "cases"):
            child = getattr(node, attr, None)
            if child is None:
                continue
            if isinstance(child, list):
                for c in child:
                    if hasattr(c, "type"):
                        _visit(c, depth + 1)
            elif hasattr(child, "type"):
                _visit(child, depth + 1)

    _visit(getattr(handler_fn, "body", None))
    if not state["reads_origin"]:
        return (False, False)
    # Čte origin. Slabé jen pokud má weak porovnání a NEMÁ striktní.
    weak = state["weak_cmp"] and not state["strict_cmp"]
    return (True, weak)


def _get_loc_col(node) -> int:
    try:
        return node.loc.start.column
    except (AttributeError, TypeError):
        return 0


def _member_path(node) -> Optional[Tuple[str, str]]:
    """For a MemberExpression like A.B, return ('A', 'B') or None.

    Doesn't recurse — only handles direct ID.member patterns. For
    chained like x.y.z, returns ('x.y' as flattened string, 'z') is NOT
    what we want — we return None for non-trivial.

    Special case: for `foo['bar']` (computed=true with Literal property),
    we treat it the same as foo.bar.
    """
    if _node_type(node) != "MemberExpression":
        return None
    obj = node.object
    prop = node.property
    obj_name = None
    if _node_type(obj) == "Identifier":
        obj_name = obj.name
    elif _node_type(obj) == "MemberExpression":
        # Try to flatten X.Y as obj_name
        inner = _member_path(obj)
        if inner is not None:
            obj_name = f"{inner[0]}.{inner[1]}"
    elif _node_type(obj) == "ThisExpression":
        obj_name = "this"
    if obj_name is None:
        return None
    # property name
    prop_name = None
    if not getattr(node, "computed", False):
        if _node_type(prop) == "Identifier":
            prop_name = prop.name
    else:
        # computed=true: foo['bar']
        if _node_type(prop) == "Literal":
            v = getattr(prop, "value", None)
            if isinstance(v, str):
                prop_name = v
    if prop_name is None:
        return None
    return (obj_name, prop_name)


def _walk(node, callback, depth: int = 0, max_depth: int = 200):
    """Generic AST walker — call callback(node) on each node in pre-order."""
    if depth > max_depth:
        return
    if not hasattr(node, "type"):
        return
    callback(node)
    # Iterate over all known child slots. Skip primitive/metadata attrs.
    # IMPORTANT: do NOT skip 'expression' — ExpressionStatement.expression
    # is the actual child node we need to walk into.
    SKIP = {
        "type", "loc", "range", "name", "value", "raw", "kind",
        "operator", "regex", "computed", "shorthand", "method",
        "prefix", "delegate", "async", "generator", "static",
        "directive",
    }
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


# ──────────────────────────────────────────────────────────────────────────────
# TAINT TRACKER
# ──────────────────────────────────────────────────────────────────────────────

class _TaintTracker:
    """Tracks which variables hold tainted (source-derived) values.

    Per-scope variable tainting is approximated globally — we don't model
    closures or block scoping. This means we'll have FP for code that
    reuses variable names in different scopes, but the rate is low for
    real-world JS where source/sink chains are short and local.
    """

    def __init__(self, source_code: str, source_name: str = "<inline>"):
        self.source_code = source_code
        self.source_name = source_name
        # var_name → list of (source_label, line, last_op)
        # We keep only the most-recent taint info per var.
        self.tainted: Dict[str, Tuple[str, int, List[Tuple[str, int]]]] = {}
        # ↑ var → (origin_source_label, origin_line, chain_so_far)
        self.findings: List[StaticFinding] = []
        # v10.16: registr message/postMessage handlerů pro origin-check audit
        self._message_handlers: List[Dict[str, Any]] = []

    # ── Source detection ────────────────────────────────────────────────
    def detect_source(self, expr) -> Optional[Tuple[str, int]]:
        """v10.76: bounded-depth wrapper around _detect_source_impl. The impl
        recurses through nested expressions with no cap; a pathologically deep
        expr in a minified/hostile bundle used to raise RecursionError mid-walk
        and abort the ENTIRE file scan. Track depth on the instance (every self-
        call counts) and bail to None past the cap instead of raising."""
        self._ds_depth = getattr(self, "_ds_depth", 0) + 1
        try:
            if self._ds_depth > 150:
                return None
            # v10.86: at the OUTERMOST call, start a fresh extraction record for
            # this expression. Nested self-calls (depth > 1) must not reset it —
            # an extraction found anywhere along the resolved path counts.
            if self._ds_depth == 1:
                self._src_extracted = False
            return self._detect_source_impl(expr)
        finally:
            self._ds_depth -= 1

    def _detect_source_impl(self, expr) -> Optional[Tuple[str, int]]:
        """Return (source_label, line) if expr is a known source expression,
        or recursively if it propagates taint."""
        line = _get_loc_line(expr)
        t = _node_type(expr)

        # v10.14: SpreadElement — `Function(...args)`, `eval(...payload)`.
        # SpreadElement.argument je underlying expression (typicky Identifier
        # pointing na array/tainted var). Transparent unwrap.
        if t == "SpreadElement":
            inner = getattr(expr, "argument", None)
            if inner is not None:
                return self.detect_source(inner)

        # v10.14: Taint terminator check — pokud je expression call na
        # known sanitizer (encodeURIComponent, DOMPurify.sanitize, ...),
        # taint NEKONTINUUJE. Return None = safe.
        if t == "CallExpression":
            callee = expr.callee
            # Global call: encodeURIComponent(x)
            if _node_type(callee) == "Identifier":
                if callee.name in _TAINT_TERMINATORS_GLOBAL:
                    return None  # taint terminates here — sanitized
            # Member call: DOMPurify.sanitize(x)
            elif _node_type(callee) == "MemberExpression":
                obj = callee.object
                prop = callee.property
                obj_name = getattr(obj, "name", None)
                prop_name = (getattr(prop, "name", None)
                             if not getattr(callee, "computed", False)
                             else None)
                if obj_name and prop_name:
                    if (obj_name, prop_name) in _TAINT_TERMINATORS_MEMBER:
                        return None  # sanitized via member call
                    if (obj_name, None) in _TAINT_TERMINATORS_MEMBER:
                        return None  # sanitized via object pattern

        # v10.14: .replace() taint reduction — pokud tainted string
        # prochází .replace() s pattern který odstraňuje < nebo >,
        # terminujeme taint (false-positive reduction). Agresivní
        # replace = dostatečná sanitize pro innerHTML context.
        if t == "CallExpression":
            callee = expr.callee
            if (_node_type(callee) == "MemberExpression" and
                    not getattr(callee, "computed", False)):
                method = getattr(callee.property, "name", "")
                if method == "replace":
                    args = expr.arguments or []
                    if len(args) >= 1:
                        first_arg = args[0]
                        # v10.76 FN fix: real sanitization = a GLOBAL regex that
                        # strips BOTH angle brackets (e.g. /[<>]/g). A substring/
                        # literal `.replace('<','')` removes only the FIRST '<',
                        # and `.replace('script','')`/`'onerror'` sanitizes nothing
                        # — terminating taint there hid real XSS (false negative).
                        rx = getattr(first_arg, "regex", None)
                        pat = flags = ""
                        if isinstance(rx, dict):
                            pat, flags = str(rx.get("pattern", "")), str(rx.get("flags", ""))
                        elif rx is not None:
                            pat = str(getattr(rx, "pattern", "") or "")
                            flags = str(getattr(rx, "flags", "") or "")
                        if "g" in flags and "<" in pat and ">" in pat:
                            # aggressive global bracket-strip — taint terminates
                            return None


        # v10.14: AwaitExpression — unwrap to inner expression.
        # `const r = await fetch(url)` → AwaitExpression wraps fetch().
        # We treat await transparently — taint flows through it.
        if t == "AwaitExpression":
            inner = getattr(expr, "argument", None)
            if inner is not None:
                # Check if inner is a taint-producing call (fetch, x.text(), etc.)
                if self._is_taint_returning_promise(inner):
                    label = "await (Promise data)"
                    # Try to extract more specific label
                    if _node_type(inner) == "CallExpression":
                        callee = inner.callee
                        if _node_type(callee) == "Identifier":
                            label = f"await {callee.name}()"
                        elif (_node_type(callee) == "MemberExpression" and
                                _node_type(callee.property) == "Identifier"):
                            label = f"await .{callee.property.name}()"
                    return label, line
                # Recursive: maybe inner has tainted sub-expression
                return self.detect_source(inner)

        # Direct member sources: location.hash, document.URL, etc.
        if t == "MemberExpression":
            mp = _member_path(expr)
            if mp and mp in _SOURCES_MEMBER:
                return _SOURCES_MEMBER[mp], line
            # v10.82 DEPTH: XHR response — receiver varies, match by property name
            if (not getattr(expr, "computed", False)
                    and _node_type(expr.property) == "Identifier"
                    and expr.property.name in _XHR_RESPONSE_PROPS):
                return f"XMLHttpRequest.{expr.property.name}", line
            # v10.14: chained member access deeper than source key
            # — e.g. history.state.html, document.location.href —
            # _member_path returns ("history.state", "html"). Try
            # splitting obj_name and re-looking in sources.
            if mp:
                obj_name = mp[0]
                # Try (root, attr) split — history.state → (history, state)
                if "." in obj_name:
                    parts = obj_name.split(".")
                    if len(parts) >= 2:
                        # Try first 2 components as source key
                        candidate = (parts[0], parts[1])
                        if candidate in _SOURCES_MEMBER:
                            return _SOURCES_MEMBER[candidate], line
            # Member on tainted variable? e.g. tainted.slice
            if mp:
                obj_name = mp[0]
                if obj_name in self.tainted:
                    src_label, src_line, _chain = self.tainted[obj_name]
                    if getattr(self, "tainted_ctrl", {}).get(obj_name):
                        self._src_extracted = True
                    # v10.86: reading a URL COMPONENT off a tainted whole-URL
                    # value (`new URL(document.URL).hash`) is an extraction.
                    if mp[1] in ("hash", "search", "pathname", "searchParams"):
                        self._src_extracted = True
                    return src_label, src_line
                # v10.14: pro chained member access typu n.data.code
                # _member_path() vrátí obj_name = "n.data" (s tečkou).
                # Zkusíme i prefix — jednotlivé komponenty, jestli je
                # některá tainted. To pokrývá MessageEvent param tracking
                # (n je tainted, takže n.data, n.data.code, n.data.x.y
                # všechno propaguje taint).
                if "." in obj_name:
                    root = obj_name.split(".", 1)[0]
                    if root in self.tainted:
                        src_label, src_line, _chain = self.tainted[root]
                        return src_label, src_line
            # v10.82 DEPTH: computed/index access on tainted data stays tainted.
            # `_member_path` returns None for a numeric / non-string-literal index,
            # so the MOST canonical DOM-XSS source expressions were silently dropped:
            #   el.innerHTML = location.hash.split('=')[1]
            #   x = location.search.split('&')[0].split('=')[1]
            #   y = taintedArr[0]
            # Recurse on the OBJECT ONLY (never the index): indexing tainted data is
            # still tainted, while cleanLookup[userInput] — where the attacker only
            # controls the KEY and the table is clean — correctly stays untainted
            # (no new false positive). The string-literal `foo['bar']` case is still
            # handled above via _member_path, so this only fires for real index/num.
            if getattr(expr, "computed", False):
                obj_src = self.detect_source(expr.object)
                if obj_src:
                    # v10.86: indexing IS an extraction — `document.URL[1]` /
                    # `x.split('#')[1]` hands the sink a slice, not the whole URL.
                    self._src_extracted = True
                    return obj_src[0], obj_src[1]

        # Identifier referring to a tainted variable
        if t == "Identifier":
            name = expr.name
            if name in self.tainted:
                src_label, src_line, _chain = self.tainted[name]
                # v10.86: carry the extraction recorded at assignment time
                if getattr(self, "tainted_ctrl", {}).get(name):
                    self._src_extracted = True
                return src_label, src_line

        # v10.76: URL-ish constructors propagate taint from their argument, so a
        # variable holding `new URLSearchParams(location.search)` / `new URL(href)`
        # is tainted and its later `.get()` is STILL caught via the tainted-object
        # path below — without the old FP of treating every `.get()` as a source.
        if t == "NewExpression":
            ncallee = getattr(expr, "callee", None)
            if (_node_type(ncallee) == "Identifier"
                    and getattr(ncallee, "name", "") in ("URLSearchParams", "URL")):
                for narg in (getattr(expr, "arguments", None) or []):
                    nsrc = self.detect_source(narg)
                    if nsrc:
                        return nsrc

        # Call with tainted argument (transitive taint)
        if t == "CallExpression":
            callee = expr.callee
            args = expr.arguments or []
            # Built-in source calls: URLSearchParams.get, localStorage.getItem
            if _node_type(callee) == "MemberExpression":
                # Get method name (last property in chain)
                method_name = None
                if not getattr(callee, "computed", False) and \
                        _node_type(callee.property) == "Identifier":
                    method_name = callee.property.name
                # v10.76: match by RECEIVER identity, not method name alone.
                # Bare Map/Redux/Immutable/config `.get()` / `$(x).get(0)` are
                # NOT URL sources; fall through to the tainted-object check below.
                if method_name in ("get", "getAll") and \
                        _is_urlsearchparams_like(callee.object):
                    # v10.86: a parameter lookup yields ONE value, already
                    # decoded and free of the origin prefix — full control.
                    self._src_extracted = True
                    return f"URLSearchParams.{method_name}", line
                if method_name == "getItem":
                    obj = callee.object
                    obj_name = (obj.name if _node_type(obj) == "Identifier"
                                else "")
                    if (obj_name in ("localStorage", "sessionStorage")
                            or obj_name.endswith("Storage")):
                        return f"{obj_name or 'storage'}.getItem", line
                # Chained call: tainted.slice(1), tainted.toUpperCase(),
                # tainted.split('&'), etc.  If the callee's OBJECT is
                # tainted (or itself a source), the call result is tainted.
                obj_src = self.detect_source(callee.object)
                if obj_src:
                    # v10.86: record whether this call can strip the origin
                    # prefix off a whole-URL source (see _EXTRACTION_METHODS).
                    if method_name in _EXTRACTION_METHODS:
                        self._src_extracted = True
                    return obj_src[0], obj_src[1]
            # Check if any arg is tainted → propagate (atob(tainted), etc.)
            for arg in args:
                src = self.detect_source(arg)
                if src:
                    return src[0], src[1]
            # If callee is itself tainted (e.g. tainted())
            callee_src = self.detect_source(callee)
            if callee_src:
                return callee_src

        # Binary expression: a + tainted, tainted + 'foo'
        if t == "BinaryExpression":
            l = self.detect_source(expr.left)
            r = self.detect_source(expr.right)
            return l or r

        # Logical expression: tainted || 'default'
        if t == "LogicalExpression":
            l = self.detect_source(expr.left)
            r = self.detect_source(expr.right)
            return l or r

        # Conditional: test ? consequent : alternate
        if t == "ConditionalExpression":
            # v10.18 (FP#1.2 — predikátový taint): taint VÝSLEDKU ternárního
            # výrazu = taint(consequent) | taint(alternate), NEZÁVISLE na
            # taint(test). `l` v  l==='en' ? A : B  je jen PODMÍNKA — neteče do
            # výsledku, jen rozhoduje větev. Dřív se `t_test` přimíchával do
            # výsledku → celá třída false-positivů (predikát označen jako source).
            #
            # Navíc: x === <konst> je NARROWING/sanitizér. Když test porovnává
            # nějakou proměnnou s konstantou, v dané větvi je ta proměnná rovna
            # konstantě — takže i kdyby `consequent`/`alternate` byly tou
            # proměnnou, ve své větvi jsou bezpečné. Detekujeme equality-narrowing
            # a v takovém případě příslušnou větev NEtaintujeme.
            # BRANCH-AWARE narrowing: `x === c` narrows x to the constant ONLY in
            # the CONSEQUENT (true) branch; in the alternate x is anything-but-c,
            # still attacker-controlled. Symmetrically `x !== c` narrows only the
            # ALTERNATE. Applying one set to BOTH branches (old behavior) dropped
            # taint from a branch where x is still tainted → missed DOM XSS, e.g.
            #   x = location.hash;  el.innerHTML = (x === 'safe') ? 'ok' : x;
            cons_narrowed, alt_narrowed = self._equality_narrowed_vars(expr.test)
            t_cons = self.detect_source(expr.consequent)
            t_alt = self.detect_source(expr.alternate)
            if t_cons and self._expr_is_narrowed_var(expr.consequent, cons_narrowed):
                t_cons = None
            if t_alt and self._expr_is_narrowed_var(expr.alternate, alt_narrowed):
                t_alt = None
            return t_cons or t_alt   # ZÁMĚRNĚ bez t_test

        # Template literal `foo${tainted}bar`
        if t == "TemplateLiteral":
            for q in (expr.expressions or []):
                src = self.detect_source(q)
                if src:
                    return src

        # v10.82 DEPTH: array literal carries taint of any element, so a
        # wrap-then-join like `[userInput].join('')` or `[a, tainted].join(' ')`
        # stays tainted (the .join() receiver is this ArrayExpression → the
        # tainted-object call path then sees it). Mirrors TemplateLiteral above.
        if t == "ArrayExpression":
            for el in (expr.elements or []):
                if el is None:   # sparse hole
                    continue
                src = self.detect_source(el)
                if src:
                    return src

        return None

    # ── Predikátový taint helpers (v10.18, FP#1.2) ─────────────────────────
    def _equality_narrowed_vars(self, test_expr):
        """Vrátí (cons_narrowed, alt_narrowed): jména proměnných rovných
        konstantě v CONSEQUENT větvi (z `x === c` / `x == c`) vs v ALTERNATE
        větvi (z `x !== c` / `x != c`). Rozdělení podle větve je klíčové:
        `x === 'en' ? A : B` sanitizuje x jen v A; v B je x cokoli kromě 'en'
        (stále tainted). Aplikovat jednu množinu na obě větve = missed XSS.

        Pokrývá:
            x === 'en'                 → cons={x}
            x !== 'en'                 → alt={x}
            x === 'en' || x === 'cs'   → cons={x}
        """
        cons: set = set()
        alt: set = set()
        if test_expr is None:
            return cons, alt

        def walk(node):
            if node is None:
                return
            nt = _safe_type(node)
            if nt == "BinaryExpression":
                op = getattr(node, "operator", "")
                left = getattr(node, "left", None)
                right = getattr(node, "right", None)
                var = None
                # x === 'literal'  nebo  'literal' === x
                if _safe_type(left) == "Identifier" and _is_literal(right):
                    var = left.name
                elif _safe_type(right) == "Identifier" and _is_literal(left):
                    var = right.name
                if var is not None:
                    if op in ("===", "=="):
                        cons.add(var)      # rovná se konstantě ve true-větvi
                    elif op in ("!==", "!="):
                        alt.add(var)       # rovná se konstantě ve false-větvi
            # Logický OR/AND řetězec porovnání → rekurze do obou stran
            if nt == "LogicalExpression":
                walk(getattr(node, "left", None))
                walk(getattr(node, "right", None))
            # Závorky / sekvence
            if nt == "SequenceExpression":
                for e in (getattr(node, "expressions", None) or []):
                    walk(e)
        walk(test_expr)
        return cons, alt

    def _expr_is_narrowed_var(self, expr, narrowed_vars):
        """True když `expr` je prostě jedna z narrowed proměnných (Identifier)."""
        if not narrowed_vars or expr is None:
            return False
        return _safe_type(expr) == "Identifier" and getattr(expr, "name", None) in narrowed_vars

    # ── CSPT2CSRF: relative-path-with-taint detection (v10.16) ──────────
    def detect_cspt_path(self, expr):
        """v10.16: Detekuje Client-Side Path Traversal sink.

        Vrátí (source_label, line) pokud `expr` je URL argument network callu,
        který je RELATIVNÍ CESTA s vloženým tainted vstupem — tj. vzorec, kde
        `../` traversal přesměruje request na jiný endpoint (CSPT2CSRF):

            fetch('/api/news/' + userInput)          BinaryExpression
            fetch(`/api/items/${param}/data`)        TemplateLiteral
            axios.get('/api/' + id)                  dtto

        Rozlišení od běžného "tainted full URL" (to už řeší detect_source):
        zajímá nás jen RELATIVNÍ cesta (začíná '/' nebo bez schématu), kde je
        tainted jen SEGMENT, ne celá URL. U plně tainted URL je to spíš SSRF/
        open-redirect (řešeno jinde), ne path traversal.

        Vrací None, pokud:
          • argument je čistý literál bez taintu,
          • celý argument je tainted (full-URL → jiná detekce),
          • je to absolutní URL s doménou (http://...).
        """
        t = _node_type(expr)

        # ── BinaryExpression: '/api/' + taint  (a možná víc concatů) ──
        if t == "BinaryExpression":
            # Posbírej "fragmenty" zleva doprava
            parts = self._flatten_concat(expr)
            if not parts:
                return None
            # První fragment musí být string literál určující relativní cestu
            first = parts[0]
            if _node_type(first) != "Literal":
                return None
            first_val = str(getattr(first, "value", "") or "")
            if not self._is_relative_path_prefix(first_val):
                return None
            # Některý NE-první fragment musí být tainted (vložený segment)
            for p in parts[1:]:
                src = self.detect_source(p)
                if src:
                    return src
            return None

        # ── TemplateLiteral: `/api/${taint}/data` ──
        if t == "TemplateLiteral":
            quasis = getattr(expr, "quasis", []) or []
            exprs = getattr(expr, "expressions", []) or []
            if not quasis or not exprs:
                return None
            # první quasi (statický prefix) musí být relativní cesta
            first_cooked = ""
            q0 = quasis[0]
            val = getattr(q0, "value", None)
            if val is not None:
                first_cooked = getattr(val, "cooked", "") or getattr(val, "raw", "") or ""
            elif isinstance(getattr(q0, "cooked", None), str):
                first_cooked = q0.cooked
            if not self._is_relative_path_prefix(first_cooked):
                return None
            # některý ${...} musí být tainted
            for e in exprs:
                src = self.detect_source(e)
                if src:
                    return src
            return None

        return None

    @staticmethod
    def _is_relative_path_prefix(s: str) -> bool:
        """True pokud string vypadá jako relativní cesta API endpointu —
        začíná '/' (ne '//', což je protocol-relative absolutní URL) a není
        absolutní http(s):// URL."""
        if not s:
            return False
        s_strip = s.strip()
        if s_strip.startswith("//"):
            return False  # protocol-relative = absolutní
        if s_strip.startswith("http://") or s_strip.startswith("https://"):
            return False
        # relativní cesta: '/api/...', './...', '../...', nebo 'api/...'
        # nejčastější a nejsilnější signál je '/'
        return s_strip.startswith("/") or s_strip.startswith("./") or \
            s_strip.startswith("../") or bool(re.match(r"^[a-zA-Z0-9_-]+/", s_strip))

    def _flatten_concat(self, node) -> List:
        """Rozloží levostranně asociovaný '+' concat strom na seznam fragmentů
        zleva doprava. ('/a/' + x + '/b') → [Literal '/a/', x, Literal '/b']."""
        out = []

        def _walk(n):
            if _node_type(n) == "BinaryExpression" and getattr(n, "operator", "") == "+":
                _walk(n.left)
                _walk(n.right)
            else:
                out.append(n)

        _walk(node)
        return out

    # ── Operation labeling ──────────────────────────────────────────────
    def _label_op(self, expr) -> str:
        """Short label describing what operation expr performs on a tainted
        value. Used in chain[] for pretty-printing."""
        t = _node_type(expr)
        if t == "CallExpression":
            callee = expr.callee
            if _node_type(callee) == "Identifier":
                return f"{callee.name}()"
            if _node_type(callee) == "MemberExpression":
                mp = _member_path(callee)
                if mp:
                    return f".{mp[1]}()"
            return "call()"
        if t == "MemberExpression":
            mp = _member_path(expr)
            if mp:
                return f".{mp[1]}"
            return ".prop"
        if t == "BinaryExpression":
            return f" {expr.operator} "
        if t == "TemplateLiteral":
            return "`...${...}...`"
        return t

    # ── Sink detection ──────────────────────────────────────────────────
    def _get_prop_name(self, member_node) -> Optional[str]:
        """Extract property name from MemberExpression, even for complex objects.
        Handles `foo.bar`, `foo.bar.baz`, `getElement('x').innerHTML`, foo['bar']."""
        if _node_type(member_node) != "MemberExpression":
            return None
        prop = member_node.property
        if not getattr(member_node, "computed", False):
            if _node_type(prop) == "Identifier":
                return prop.name
        else:
            # foo['bar']
            if _node_type(prop) == "Literal":
                v = getattr(prop, "value", None)
                if isinstance(v, str):
                    return v
        return None

    def check_sink(self, node):
        """Look at node — is it a sink? If yes, check if its argument/RHS is
        tainted, and if so, emit a finding."""

        t = _node_type(node)

        # Assignment: ANYTHING.innerHTML = source
        # (object can be any expression — element ref, function call result, etc.)
        if t == "AssignmentExpression" and node.operator == "=":
            left = node.left
            right = node.right
            if _node_type(left) == "MemberExpression":
                prop_name = self._get_prop_name(left)
                if prop_name and prop_name in _SINKS_ASSIGN:
                    sink_label, severity = _SINKS_ASSIGN[prop_name]
                    src = self.detect_source(right)
                    if src:
                        self._emit_finding(
                            source_name=src[0],
                            sink_name=sink_label,
                            line=_get_loc_line(node),
                            col=_get_loc_col(node),
                            severity=severity,
                            chain_extra=[
                                (src[0], src[1]),
                                (f"={sink_label}", _get_loc_line(node)),
                            ],
                        )
                # location.href = "javascript:..." special case
                # (LHS object MUST be the literal 'location' identifier)
                obj = left.object
                if (_node_type(obj) == "Identifier" and obj.name == "location"
                        and prop_name in ("href",)):
                    src = self.detect_source(right)
                    if src:
                        self._emit_finding(
                            source_name=src[0],
                            sink_name="location.href(scheme)",
                            line=_get_loc_line(node),
                            col=_get_loc_col(node),
                            severity="medium",
                            chain_extra=[
                                (src[0], src[1]),
                                ("=location.href", _get_loc_line(node)),
                            ],
                        )

        # CallExpression: eval(...), Function(...), document.write(...), $().html(...)
        # v10.14: NewExpression (new Function(x), new Worker(url), new Image()
        # → .src = url) má stejnou strukturu — callee + arguments. Pro sink
        # detekci je treat as CallExpression. To pokrývá `new Function(code)`
        # což je equivalent eval pro WAF bypass.
        if t == "CallExpression" or t == "NewExpression":
            callee = node.callee
            args = node.arguments or []

            # v10.14b: dynamic import(taintedUrl) — callee.type == "Import"
            # import(x) načte arbitrary module URL — pokud tainted, útočník
            # může načíst vlastní skript.
            if _node_type(callee) == "Import":
                if args:
                    src = self.detect_source(args[0])
                    if src:
                        self._emit_finding(
                            source_name=src[0],
                            sink_name="dynamic import(url)",
                            line=_get_loc_line(node),
                            col=_get_loc_col(node),
                            severity="high",
                            chain_extra=[(src[0], src[1]),
                                         ("import()", _get_loc_line(node))],
                        )
                return  # handled

            # v10.82 DEPTH: indirect eval via the comma operator — `(0,eval)(x)`
            # and `(0,Function)(x)` are the classic indirect-eval forms (run in
            # global scope, common WAF/CSP-bypass idiom). The callee is a
            # SequenceExpression whose LAST element is the Identifier eval/Function.
            # Resolve it so the global-sink branch fires. (window.eval / window['eval']
            # are already caught as member sinks; setTimeout is intentionally NOT
            # resolved indirectly to avoid over-firing.)
            _indirect_name = None
            if _node_type(callee) == "SequenceExpression":
                _seq = getattr(callee, "expressions", None) or []
                if (_seq and _node_type(_seq[-1]) == "Identifier"
                        and _seq[-1].name in ("eval", "Function")):
                    _indirect_name = _seq[-1].name

            # Identifier callees: eval, Function, setTimeout, setInterval,
            # html_tag (Svelte runtime)
            if _node_type(callee) == "Identifier" or _indirect_name:
                name = (callee.name if _node_type(callee) == "Identifier"
                        else _indirect_name)
                # v10.16: CSPT2CSRF — fetch('/api/' + taint) / fetch(`/api/${t}`)
                # Relativní cesta s vloženým tainted segmentem → ../ traversal
                # přesměruje request na jiný endpoint (CSRF/IDOR).
                if name == "fetch" and args:
                    cspt = self.detect_cspt_path(args[0])
                    if cspt:
                        self._emit_finding(
                            source_name=cspt[0],
                            sink_name="fetch() [client-side path traversal]",
                            line=_get_loc_line(node),
                            col=_get_loc_col(node),
                            severity="high",
                            chain_extra=[(cspt[0], cspt[1]),
                                         ("fetch(relative-path)", _get_loc_line(node))],
                            confidence=0.75,
                        )
                # v10.14b: Worker/SharedWorker constructor — url injection
                if name in ("Worker", "SharedWorker") and args:
                    src = self.detect_source(args[0])
                    if src:
                        self._emit_finding(
                            source_name=src[0],
                            sink_name=f"{name}(url)",
                            line=_get_loc_line(node),
                            col=_get_loc_col(node),
                            severity="high",
                            chain_extra=[(src[0], src[1]),
                                         (f"new {name}()", _get_loc_line(node))],
                        )
                # ── v8: Svelte html_tag(target, value) — global runtime helper ──
                if name == "html_tag" and len(args) >= 2:
                    src = self.detect_source(args[1])
                    if src:
                        sink_label, severity = _SINKS_SVELTE_HTML["html_tag"]
                        self._emit_finding(
                            source_name=src[0],
                            sink_name=sink_label,
                            line=_get_loc_line(node),
                            col=_get_loc_col(node),
                            severity=severity,
                            confidence=0.7,
                            chain_extra=[
                                (src[0], src[1]),
                                (f"{sink_label}(...)",
                                 _get_loc_line(node)),
                            ],
                        )
                # v10.76: Worker/SharedWorker already emitted by the dedicated
                # block above — exclude them here so the finding isn't duplicated.
                if name in _SINKS_CALL_GLOBAL and name not in ("Worker", "SharedWorker"):
                    sink_label, severity = _SINKS_CALL_GLOBAL[name]
                    # For setTimeout/setInterval, only string arg counts
                    is_string_only = name in ("setTimeout", "setInterval")
                    if args:
                        first = args[0]
                        if is_string_only:
                            # Skip if the first arg is clearly a function (FunctionExpression)
                            if _node_type(first) in ("FunctionExpression",
                                                      "ArrowFunctionExpression"):
                                return
                        src = self.detect_source(first)
                        if src:
                            self._emit_finding(
                                source_name=src[0],
                                sink_name=sink_label,
                                line=_get_loc_line(node),
                                col=_get_loc_col(node),
                                severity=severity,
                                chain_extra=[
                                    (src[0], src[1]),
                                    (f"{sink_label}(...)",
                                     _get_loc_line(node)),
                                ],
                            )

            # Member callees: document.write(x), elem.innerHTML(x via setAttr...),
            # $.html(x), $(...).html(x)
            if _node_type(callee) == "MemberExpression":
                method = self._get_prop_name(callee)
                # v10.16: CSPT2CSRF — network call přes member callee:
                #   axios.get('/api/'+t) / axios.post(...) / $.ajax({url:...})
                #   $.get('/api/'+t) / xhr.open('GET', '/api/'+t)
                # URL argument = relativní cesta s tainted segmentem.
                if method in ("get", "post", "put", "delete", "patch", "ajax",
                              "request", "open", "load"):
                    # xhr.open(method, url) → URL je 2. argument; jinak 1.
                    url_arg = None
                    if method == "open" and len(args) >= 2:
                        url_arg = args[1]
                    elif args:
                        url_arg = args[0]
                    if url_arg is not None:
                        cspt = self.detect_cspt_path(url_arg)
                        if cspt:
                            obj_label = method
                            ob = getattr(callee, "object", None)
                            if _node_type(ob) == "Identifier":
                                obj_label = f"{ob.name}.{method}"
                            self._emit_finding(
                                source_name=cspt[0],
                                sink_name=f"{obj_label}() [client-side path traversal]",
                                line=_get_loc_line(node),
                                col=_get_loc_col(node),
                                severity="high",
                                chain_extra=[(cspt[0], cspt[1]),
                                             (f"{obj_label}(relative-path)",
                                              _get_loc_line(node))],
                                confidence=0.7,
                            )
                if method:
                    # v10.59: Service Worker registration —
                    #   navigator.serviceWorker.register(url) / swContainer.register(url)
                    # A Service Worker controls EVERY request in its scope and
                    # persists across reloads, so a tainted script URL is a
                    # persistent, full-origin compromise (worse than reflected XSS).
                    # Object-chain aware: only flag when the receiver is a
                    # serviceWorker container — never a generic `.register()`.
                    if method == "register" and args:
                        _swobj = getattr(callee, "object", None)
                        _obj_is_sw = (
                            (_node_type(_swobj) == "MemberExpression"
                             and self._get_prop_name(_swobj) == "serviceWorker")
                            or (_node_type(_swobj) == "Identifier"
                                and "serviceworker" in
                                (getattr(_swobj, "name", "") or "").lower()))
                        if _obj_is_sw:
                            src = self.detect_source(args[0])
                            if src:
                                self._emit_finding(
                                    source_name=src[0],
                                    sink_name="serviceWorker.register(url)",
                                    line=_get_loc_line(node),
                                    col=_get_loc_col(node),
                                    severity="critical",
                                    chain_extra=[
                                        (src[0], src[1]),
                                        ("serviceWorker.register()",
                                         _get_loc_line(node))],
                                )
                    # v10.14: setAttribute('href'|'src'|..., tainted) —
                    # context-aware sink. Posloucháme jen na nebezpečné
                    # atributy, jinak je to běžné setAttribute volání.
                    if method == "setAttribute" and len(args) >= 2:
                        first_arg = args[0]
                        attr_name = None
                        if (_node_type(first_arg) == "Literal" and
                                isinstance(getattr(first_arg, "value", None), str)):
                            attr_name = first_arg.value.lower()
                        # Nebezpečné atributy: href, src, formaction,
                        # action, data, xlink:href, srcdoc, onclick, ...
                        dangerous_attrs = {
                            "href", "src", "formaction", "action", "data",
                            "xlink:href", "srcdoc",
                        }
                        # Event handlery jako onclick, onerror — všechny on*
                        is_event_handler = (attr_name and
                                            attr_name.startswith("on"))
                        is_dangerous_url = attr_name in dangerous_attrs
                        if attr_name and (is_dangerous_url or is_event_handler):
                            value_arg = args[1]
                            src = self.detect_source(value_arg)
                            if src:
                                self._emit_finding(
                                    source_name=src[0],
                                    sink_name=f"setAttribute('{attr_name}')",
                                    line=_get_loc_line(node),
                                    col=_get_loc_col(node),
                                    severity=("critical" if is_event_handler
                                              else "high"),
                                    chain_extra=[
                                        (src[0], src[1]),
                                        (f"setAttribute('{attr_name}',...)",
                                         _get_loc_line(node)),
                                    ],
                                )

                    # document.write / writeln / insertAdjacentHTML / etc.
                    if method in _SINKS_CALL_MEMBER:
                        sink_label, severity = _SINKS_CALL_MEMBER[method]
                        # check args (insertAdjacentHTML takes 2 args, html is index 1)
                        if method == "insertAdjacentHTML" and len(args) >= 2:
                            target_arg = args[1]
                        else:
                            target_arg = args[0] if args else None
                        if target_arg:
                            src = self.detect_source(target_arg)
                            if src:
                                self._emit_finding(
                                    source_name=src[0],
                                    sink_name=sink_label,
                                    line=_get_loc_line(node),
                                    col=_get_loc_col(node),
                                    severity=severity,
                                    chain_extra=[
                                        (src[0], src[1]),
                                        (f".{method}()",
                                         _get_loc_line(node)),
                                    ],
                                )

                    # v10.14b: postMessage(sensitiveData, "*") — info-leak.
                    # Pokud je první argument tainted (cookie, token, ...),
                    # a druhý argument je "*", může dojít k cross-origin
                    # data leaku.
                    if method == "postMessage" and len(args) >= 2:
                        target_origin_arg = args[1]
                        is_wildcard = (
                            _node_type(target_origin_arg) == "Literal" and
                            getattr(target_origin_arg, "value", None) == "*"
                        )
                        if is_wildcard and args:
                            src = self.detect_source(args[0])
                            if src:
                                self._emit_finding(
                                    source_name=src[0],
                                    sink_name="postMessage(data, '*')",
                                    line=_get_loc_line(node),
                                    col=_get_loc_col(node),
                                    severity="medium",
                                    chain_extra=[
                                        (src[0], src[1]),
                                        ("postMessage(*, '*')",
                                         _get_loc_line(node)),
                                    ],
                                )
                    # jQuery-style .html()/.append() etc.
                    if method in _SINKS_JQUERY_LIKE:
                        sink_label, severity = _SINKS_JQUERY_LIKE[method]
                        if args:
                            src = self.detect_source(args[0])
                            if src:
                                self._emit_finding(
                                    source_name=src[0],
                                    sink_name=sink_label,
                                    line=_get_loc_line(node),
                                    col=_get_loc_col(node),
                                    severity=severity,
                                    confidence=0.6,
                                    chain_extra=[
                                        (src[0], src[1]),
                                        (f"{sink_label}",
                                         _get_loc_line(node)),
                                    ],
                                )
                    # ── v8: Angular DomSanitizer.bypassSecurityTrust* methods ──
                    # Direct call: sanitizer.bypassSecurityTrustHtml(userInput)
                    # Argument is what gets marked trusted; if tainted → bug.
                    if method in _SINKS_ANGULAR_BYPASS:
                        sink_label, severity = _SINKS_ANGULAR_BYPASS[method]
                        if args:
                            src = self.detect_source(args[0])
                            if src:
                                self._emit_finding(
                                    source_name=src[0],
                                    sink_name=sink_label,
                                    line=_get_loc_line(node),
                                    col=_get_loc_col(node),
                                    severity=severity,
                                    confidence=0.85,
                                    chain_extra=[
                                        (src[0], src[1]),
                                        (f"{sink_label}(...)",
                                         _get_loc_line(node)),
                                    ],
                                )

        # ── v8: React dangerouslySetInnerHTML object property ──
        # Pattern: { dangerouslySetInnerHTML: { __html: tainted } }
        # Walker visits ObjectExpression — check its properties.
        if t == "ObjectExpression":
            for prop in (getattr(node, "properties", None) or []):
                if _node_type(prop) != "Property":
                    continue
                key = getattr(prop, "key", None)
                if key is None:
                    continue
                key_name = None
                if _node_type(key) == "Identifier":
                    key_name = key.name
                elif _node_type(key) == "Literal":
                    v = getattr(key, "value", None)
                    if isinstance(v, str):
                        key_name = v
                if key_name not in _SINKS_FRAMEWORK_PROP:
                    continue
                # Found dangerouslySetInnerHTML — value should be { __html: x }
                value = getattr(prop, "value", None)
                if value is None:
                    continue
                # Drill into nested __html property
                tainted_node = None
                if _node_type(value) == "ObjectExpression":
                    for inner in (getattr(value, "properties", None) or []):
                        if _node_type(inner) != "Property":
                            continue
                        inner_key = getattr(inner, "key", None)
                        inner_key_name = None
                        if inner_key is not None:
                            if _node_type(inner_key) == "Identifier":
                                inner_key_name = inner_key.name
                            elif _node_type(inner_key) == "Literal":
                                v = getattr(inner_key, "value", None)
                                if isinstance(v, str):
                                    inner_key_name = v
                        if inner_key_name == "__html":
                            tainted_node = getattr(inner, "value", None)
                            break
                else:
                    # Variable reference: dangerouslySetInnerHTML={htmlObj}
                    tainted_node = value

                if tainted_node is None:
                    continue
                src = self.detect_source(tainted_node)
                if src:
                    sink_label, severity = _SINKS_FRAMEWORK_PROP[key_name]
                    self._emit_finding(
                        source_name=src[0],
                        sink_name=sink_label,
                        line=_get_loc_line(prop),
                        col=_get_loc_col(prop),
                        severity=severity,
                        confidence=0.9,
                        chain_extra=[
                            (src[0], src[1]),
                            (f"{sink_label}",
                             _get_loc_line(prop)),
                        ],
                    )

    # ── Variable assignment tracking ────────────────────────────────────
    def track_assignment(self, var_name: str, init_node):
        """When `var x = init_node`, check if init is tainted; if so,
        mark var as tainted with the chain."""
        if init_node is None:
            return
        src = self.detect_source(init_node)
        if src:
            op = self._label_op(init_node)
            existing_chain = []
            if isinstance(init_node, type(init_node)):
                # If init was itself a chain on tainted, extend
                t = _node_type(init_node)
                if t in ("CallExpression", "MemberExpression",
                          "BinaryExpression"):
                    inner_var = None
                    if t == "CallExpression":
                        callee = init_node.callee
                        if _node_type(callee) == "Identifier":
                            ident = callee.name
                            for arg in (init_node.arguments or []):
                                if _node_type(arg) == "Identifier":
                                    inner_var = arg.name
                                    break
                        elif _node_type(callee) == "MemberExpression":
                            obj = callee.object
                            if _node_type(obj) == "Identifier":
                                inner_var = obj.name
                    elif t == "MemberExpression":
                        obj = init_node.object
                        if _node_type(obj) == "Identifier":
                            inner_var = obj.name
                    if inner_var and inner_var in self.tainted:
                        existing_chain = list(self.tainted[inner_var][2])
            chain = existing_chain + [(op, _get_loc_line(init_node))]
            self.tainted[var_name] = (src[0], src[1], chain)
            # v10.86: remember whether the RHS extracted a slice out of a
            # whole-URL source. `var p = document.URL.split('#')[1]` must stay
            # fully attacker-controlled when `p` later reaches a sink, while
            # `var p = document.URL` must not.
            if not hasattr(self, "tainted_ctrl"):
                self.tainted_ctrl = {}
            self.tainted_ctrl[var_name] = bool(getattr(self, "_src_extracted", False))
        else:
            # v10.76 FP fix: a definite `=` / VariableDeclarator assignment with a
            # CLEAN or sanitized RHS must OVERWRITE prior taint, not preserve it.
            #   v = location.hash; v = DOMPurify.sanitize(v); el.innerHTML = v;
            # left v tainted from the first assignment → false positive on the
            # idiomatic sanitize-in-place pattern. Untaint on the clean path.
            self.tainted.pop(var_name, None)

    def visit(self, node):
        """Visitor — called for every AST node."""
        t = _node_type(node)
        # Variable declarations
        if t == "VariableDeclarator":
            if _node_type(node.id) == "Identifier" and node.init is not None:
                self.track_assignment(node.id.name, node.init)
        # Assignments to identifier
        if t == "AssignmentExpression" and node.operator == "=":
            if _node_type(node.left) == "Identifier":
                self.track_assignment(node.left.name, node.right)
        # v10.14: message handler param registration
        # window.addEventListener("message", function(e) { ... })
        # window.onmessage = function(e) { ... }
        # → marks `e` (first param) as tainted source MessageEvent.data
        self._register_message_handler_param(node)
        # v10.14: Promise .then(callback) registration
        # fetch(url).then(r => r.text()).then(t => el.innerHTML = t)
        # navigator.clipboard.readText().then(text => ...)
        # → marks callback's first parameter as tainted (response data)
        self._register_promise_then_callback(node)
        # Sink detection
        self.check_sink(node)

    def _register_message_handler_param(self, node):
        """v10.14: Registruje parametr message/event handleru jako tainted
        source. Tím se `e.data`, `e.detail`, atd. automaticky propaguje
        přes existující taint logiku do sinks (innerHTML, eval, Function).

        Aktivuje se pro:
          1. addEventListener("message"|"messageerror"|"custom-*", fn)
          2. receiver.onmessage = fn  (window, document, BroadcastChannel, ws)
          3. receiver.on<custom> = fn  (CustomEvent receivers)

        Event types které jsou bezpečné (event je internal, ne attacker-controlled)
        explicitně vyloučíme:
          - load, error, click, mouseover, ... (DOM lifecycle/UI)
        Zaměříme se na messaging eventy:
          - message, messageerror (postMessage, WebSocket, BroadcastChannel,
            ServiceWorker, MessagePort)
          - storage (cross-tab data via localStorage)
          - custom events (uživatelsky definované — attacker může dispatchnout)
        """
        t = _node_type(node)

        handler_fn = None
        param_label_source = None

        # Definice event types které carry attacker-controlled data
        # Message-family: postMessage, WebSocket, BroadcastChannel, etc.
        _MESSAGING_EVENTS = {"message", "messageerror"}
        # Storage events nesou data z localStorage (cross-tab attacker)
        _STORAGE_EVENTS = {"storage"}
        # v10.16: Route/navigation events — SPA routery na nich staví.
        # hashchange: e.newURL / e.oldURL nesou URL (útočník řídí #fragment).
        # popstate: e.state nese history state object. Handler typicky čte
        # location.hash/search a renderuje route do DOMu → DOM XSS.
        _ROUTE_EVENTS = {"hashchange", "popstate"}
        # UI/lifecycle events bezpečné — ne carry data od útočníka
        _SAFE_EVENT_TYPES = {
            "load", "error", "click", "dblclick", "mouseover", "mouseout",
            "mousedown", "mouseup", "mousemove", "keyup", "keydown",
            "keypress", "focus", "blur", "submit", "change", "input",
            "scroll", "resize", "abort", "beforeunload", "unload",
            "DOMContentLoaded", "readystatechange", "open", "close",
        }

        # Case 1: addEventListener("<event>", handler)
        if t == "CallExpression":
            callee = node.callee
            args = node.arguments or []
            if (_node_type(callee) == "MemberExpression" and
                    not getattr(callee, "computed", False) and
                    _node_type(callee.property) == "Identifier" and
                    callee.property.name == "addEventListener" and
                    len(args) >= 2):
                first = args[0]
                if (_node_type(first) == "Literal" and
                        isinstance(getattr(first, "value", None), str)):
                    event_type = first.value
                    if event_type in _MESSAGING_EVENTS:
                        handler_fn = args[1]
                        param_label_source = "MessageEvent.data"
                    elif event_type in _STORAGE_EVENTS:
                        handler_fn = args[1]
                        param_label_source = "StorageEvent.newValue"
                    elif event_type in _ROUTE_EVENTS:
                        # hashchange/popstate — event param nese route data
                        # (e.newURL / e.state). Handler navíc typicky čte
                        # location.hash/search (to už je tainted source sám).
                        handler_fn = args[1]
                        param_label_source = (
                            "HashChangeEvent.newURL"
                            if event_type == "hashchange"
                            else "PopStateEvent.state")
                    # v10.76 FP fix: the old `elif event_type not in
                    # _SAFE_EVENT_TYPES` branch tainted the handler param for ANY
                    # unlisted event — transitionend/animationend/wheel/pointerdown/
                    # contextmenu/drop/paste/… — then `e.<anything>` flowed to sinks
                    # as a false positive. Only the explicit messaging/storage/route
                    # events above carry attacker-controlled data; unknown events no
                    # longer over-taint.

        # Case 2: receiver.on<event> = fn  (assignment)
        # Pokrývá: window.onmessage, bc.onmessage, document.onstorage,
        # element.oncustom-handler, atd.
        if t == "AssignmentExpression" and node.operator == "=":
            left = node.left
            if (_node_type(left) == "MemberExpression" and
                    not getattr(left, "computed", False) and
                    _node_type(left.property) == "Identifier"):
                prop_name = left.property.name or ""
                if prop_name.startswith("on") and len(prop_name) > 2:
                    event_type = prop_name[2:].lower()
                    if event_type in _MESSAGING_EVENTS:
                        handler_fn = node.right
                        param_label_source = "MessageEvent.data"
                    elif event_type in _STORAGE_EVENTS:
                        handler_fn = node.right
                        param_label_source = "StorageEvent.newValue"
                    elif event_type in _ROUTE_EVENTS:
                        # window.onhashchange / window.onpopstate
                        handler_fn = node.right
                        param_label_source = (
                            "HashChangeEvent.newURL"
                            if event_type == "hashchange"
                            else "PopStateEvent.state")
                    # Pro on<event> property nebudeme registrovat
                    # neznámé events jako tainted — riziko false-positive
                    # je vyšší (běžně se používají standardní handlery
                    # jako onclick, onload, onerror, které jsou safe).

        if handler_fn is None or param_label_source is None:
            return

        # handler_fn musí být function (FunctionExpression / ArrowFunction)
        fn_type = _node_type(handler_fn)
        if fn_type not in ("FunctionExpression", "ArrowFunctionExpression",
                            "FunctionDeclaration"):
            return

        # Extrahnout první parametr (název)
        params = getattr(handler_fn, "params", None) or []
        if not params:
            return
        first_param = params[0]
        if _node_type(first_param) != "Identifier":
            return
        param_name = first_param.name
        if not param_name:
            return

        # Označit parametr jako tainted source. Chain prázdná — je to
        # vstupní bod taintu. existing_chain neexistuje pro fresh param.
        line = _get_loc_line(handler_fn)
        self.tainted[param_name] = (param_label_source, line, [])

        # v10.16: HIGH-VALUE — postMessage/message handler bez origin check.
        # Když handler bere attacker-controlled data (MessageEvent.data) a
        # NEvaliduje event.origin, je to klasický cross-origin DOM XSS
        # (vysoký payout na bug bounty). Zaznamenáme handler + jestli někde
        # v těle čte/porovnává `<param>.origin`. Vyhodnotí se po doběhnutí
        # analýzy: handler bez origin check + data→sink chain = high/critical.
        if param_label_source == "MessageEvent.data":
            checks_origin, weak_origin = _handler_checks_origin(
                handler_fn, param_name)
            self._message_handlers.append({
                "param": param_name,
                "line": line,
                "validates_origin": checks_origin,
                "weak_origin": weak_origin,
                "fn": handler_fn,
            })

    def _register_promise_then_callback(self, node):
        """v10.14: Detekuje Promise .then(callback) na známých
        taint-producing zdrojích a označí callback's první parametr
        jako tainted.

        Pokrývá:
          - fetch(url).then(r => ...)              [r = Response]
          - response.text().then(t => ...)         [t = string]
          - response.json().then(j => ...)         [j = parsed JSON]
          - clipboard.readText().then(t => ...)    [t = clipboard string]
          - localStorage.getItem(...).then(...)    [edge]
          - blob.text().then(...)
          - FileReader-style readAsText then

        Chained .then patterns:
          fetch(url).then(r => r.text()).then(t => innerHTML = t)
                                          ^^^^^^^^^^^^^^^^^^^^^^
          Outer .then se zachytí — vnitřní r.text() vrátí Promise,
          další .then dostane string. Analýza statická = mark obě
          callback params jako tainted.
        """
        if _node_type(node) != "CallExpression":
            return
        callee = node.callee
        if _node_type(callee) != "MemberExpression":
            return
        if getattr(callee, "computed", False):
            return
        if _node_type(callee.property) != "Identifier":
            return
        method = callee.property.name
        if method != "then":
            return

        # `obj.then(cb)` — co je obj?
        # Zkontrolujeme, jestli obj je taint-producing call:
        #   - fetch(...)
        #   - response.text() / response.json() / response.blob()
        #   - navigator.clipboard.readText() / .read()
        #   - blob.text()
        obj_call = callee.object
        if _node_type(obj_call) != "CallExpression":
            return

        # Zjisti, co je callee toho obj_call
        sub_callee = obj_call.callee
        is_taint_promise = False
        promise_source_label = "Promise.then() callback"

        if _node_type(sub_callee) == "Identifier":
            # fetch(url) — global identifier
            if sub_callee.name in ("fetch",):
                is_taint_promise = True
                promise_source_label = "fetch().then(Response)"
        elif _node_type(sub_callee) == "MemberExpression":
            # response.text(), navigator.clipboard.readText(), atd.
            if (not getattr(sub_callee, "computed", False) and
                    _node_type(sub_callee.property) == "Identifier"):
                method_called = sub_callee.property.name
                # Taint-producing methods
                if method_called in (
                    "text", "json", "blob", "arrayBuffer",
                    "formData", "readText", "read", "clone",
                ):
                    is_taint_promise = True
                    promise_source_label = f".{method_called}().then(data)"
                # v10.14: chained .then — obj_call je sám .then() jehož
                # callback returns taint-producing call.
                # Pattern: fetch(url).then(r => r.text()).then(t => ...)
                #                    ^^^^^^^^^^^^^^^^^^   ← obj_call
                # outer .then callback je r => r.text(). Pokud výraz
                # vrací taint-producing promise, mark current callback
                # param jako tainted.
                elif method_called == "then":
                    # Podívej se na argument předchozího .then
                    prev_args = obj_call.arguments or []
                    if prev_args:
                        prev_cb = prev_args[0]
                        if _node_type(prev_cb) == "ArrowFunctionExpression":
                            body = prev_cb.body
                            # Arrow expression body (no braces) → direct expr
                            if self._is_taint_returning_promise(body):
                                is_taint_promise = True
                                promise_source_label = (
                                    "chained .then() Promise data"
                                )
                        elif _node_type(prev_cb) == "FunctionExpression":
                            # function(r) { return r.text(); }
                            body = prev_cb.body
                            if _node_type(body) == "BlockStatement":
                                for stmt in (body.body or []):
                                    if _node_type(stmt) == "ReturnStatement":
                                        if (stmt.argument and
                                                self._is_taint_returning_promise(
                                                    stmt.argument)):
                                            is_taint_promise = True
                                            promise_source_label = (
                                                "chained .then() Promise data"
                                            )
                                            break

        if not is_taint_promise:
            return

        # callback je první argument .then
        args = node.arguments or []
        if not args:
            return
        callback = args[0]
        cb_type = _node_type(callback)
        if cb_type not in ("FunctionExpression", "ArrowFunctionExpression"):
            return

        params = getattr(callback, "params", None) or []
        if not params:
            return
        first_param = params[0]
        if _node_type(first_param) != "Identifier":
            return
        param_name = first_param.name
        if not param_name:
            return

        # Mark callback's first param jako tainted source
        line = _get_loc_line(callback)
        self.tainted[param_name] = (promise_source_label, line, [])

    def _is_taint_returning_promise(self, expr) -> bool:
        """Helper pro chained .then detection.

        Vrátí True pokud expression je call vracející taint-producing
        Promise — t.j. fetch(), x.text(), x.json(), x.readText(), atd.
        Slouží k tomu, že outer .then(r => r.text()) je rozpoznán jako
        chain producent — další .then dostane tainted parametr.
        """
        if _node_type(expr) != "CallExpression":
            return False
        callee = expr.callee
        if _node_type(callee) == "Identifier" and callee.name == "fetch":
            return True
        if _node_type(callee) == "MemberExpression":
            if (not getattr(callee, "computed", False) and
                    _node_type(callee.property) == "Identifier"):
                method = callee.property.name
                if method in ("text", "json", "blob", "arrayBuffer",
                              "formData", "readText", "read", "clone"):
                    return True
                # v10.14: .then(callback) on taint-producing object —
                # recursively check if obj.then() chain produces taint
                if method == "then":
                    obj = callee.object
                    if self._is_taint_returning_promise(obj):
                        return True
        return False

    def _emit_finding(self, source_name: str, sink_name: str,
                      line: int, col: int, severity: str,
                      chain_extra: List[Tuple[str, int]] = None,
                      confidence: float = 0.8):
        # Snippet
        snippet = self._extract_snippet(line, col)

        # ── v10.86: weight the finding by how much of the value the attacker
        # actually controls, not by the sink alone. Severity used to come from
        # the SINK only, so `eval(document.URL)` scored the same critical as
        # `eval(location.hash.substr(1))` even though the first cannot fire
        # (the URL is not valid JS). Measured cost of the old behaviour on the
        # Firing Range corpus: 64 false positives at high/critical.
        control = classify_controllability(
            source_name, bool(getattr(self, "_src_extracted", False)))
        if control == CONTROL_NONE:
            # Fixed route / own origin — nothing here is attacker-supplied.
            severity, confidence = "info", min(confidence, 0.25)
        elif control == CONTROL_PREFIXED:
            # Real data flow, but the origin prefix rides along unremoved, so it
            # is a lead to review rather than a live bug. Still reported — one
            # `.split()` away from being exploitable.
            severity = "low" if severity in ("critical", "high") else "info"
            confidence = min(confidence, 0.4)

        f = StaticFinding(
            source_name=source_name,
            sink_name=sink_name,
            chain=chain_extra or [(source_name, line), (sink_name, line)],
            severity=severity,
            confidence=confidence,
            file=self.source_name,
            line=line,
            col=col,
            snippet=snippet,
            controllability=control,
        )
        self.findings.append(f)

    def _extract_snippet(self, line: int, col: int) -> str:
        """Extract ~100 chars around (line, col)."""
        if line <= 0:
            return ""
        try:
            lines = self.source_code.split("\n")
            if line > len(lines):
                return ""
            target = lines[line - 1]
            return target.strip()[:140]
        except Exception:
            return ""


# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ──────────────────────────────────────────────────────────────────────────────

def analyze_js_source(source_code: str,
                       source_name: str = "<inline>") -> List[StaticFinding]:
    """Parse and analyze JavaScript source code; return all source→sink
    chains found.

    Returns empty list if esprima unavailable or parsing fails.
    """
    if not _ESPRIMA_AVAILABLE:
        return []
    if not source_code or not source_code.strip():
        return []

    try:
        tree = esprima.parseScript(
            source_code,
            options={"loc": True, "range": True, "tolerant": True}
        )
    except Exception as e:
        # Fall back to module parsing for ES6+
        try:
            tree = esprima.parseModule(
                source_code,
                options={"loc": True, "range": True, "tolerant": True}
            )
        except Exception as e2:
            log.debug("esprima parse failed: %s / %s", e, e2)
            return []

    tracker = _TaintTracker(source_code, source_name)
    try:
        _walk(tree, tracker.visit)
    except RecursionError:
        # detect_source() recurses through nested expressions WITHOUT a depth cap
        # (unlike _walk's max_depth). A pathologically deep expression in a hostile
        # or obfuscated bundle (e.g. a+a+a+…×thousands) can overflow Python's
        # recursion limit. Keep whatever findings were collected rather than
        # crashing the whole static-JS phase on one bad script.
        log.debug("static JS analysis hit recursion limit on %s", source_name)
    except Exception as _e:  # best-effort: one bad script must not kill the phase
        log.debug("static JS analysis error on %s: %s", source_name, _e)

    # v10.16: HIGH-VALUE — postMessage/message handler bez origin validace.
    # Pokud handler bere MessageEvent.data a teče do sinku BEZ kontroly
    # event.origin, je to cross-origin DOM XSS (vysoký payout). Najdeme
    # findings pocházející z MessageEvent.data a u těch z handleru bez
    # origin checku zvýšíme severity a označíme.
    # v10.16: HIGH-VALUE — postMessage/message handler bez origin validace
    # NEBO se slabou (bypassovatelnou) validací. Oboje = cross-origin DOM XSS
    # (vysoký payout). Missing origin: e.data → sink bez čtení e.origin.
    # Weak origin: e.origin.indexOf("trusted")!==-1 (obejde
    # trusted.attacker.com). Striktní (===) handler neeskalujeme.
    _missing = [h for h in tracker._message_handlers
                if not h["validates_origin"]]
    _weak = [h for h in tracker._message_handlers
             if h["validates_origin"] and h.get("weak_origin")]
    if _missing or _weak:
        for f in tracker.findings:
            src = (f.source_name or "")
            if "MessageEvent.data" in src:
                f.severity = "high"
                f.confidence = max(f.confidence, 0.85)
                if _missing and "origin" not in (f.sink_name or ""):
                    f.sink_name = f"{f.sink_name} [postMessage, no origin check]"
                elif _weak and "origin" not in (f.sink_name or ""):
                    f.sink_name = (f"{f.sink_name} "
                                   f"[postMessage, weak origin check — bypassable]")
        _has_msg_finding = any("MessageEvent.data" in (f.source_name or "")
                               for f in tracker.findings)
        if not _has_msg_finding:
            for h in _missing:
                tracker.findings.append(StaticFinding(
                    source_name="MessageEvent.data",
                    sink_name="message handler without origin validation",
                    chain=[("addEventListener('message')", h["line"])],
                    severity="medium",
                    confidence=0.6,
                    file=source_name,
                    line=h["line"],
                    snippet="postMessage handler reads event.data but never "
                            "validates event.origin",
                ))
    return tracker.findings


# ──────────────────────────────────────────────────────────────────────────────
# HTML INLINE SCRIPT EXTRACTION
# ──────────────────────────────────────────────────────────────────────────────

# Pattern for <script>…</script> block (without src attribute)
_RE_INLINE_SCRIPT = re.compile(
    r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)
# Pattern for external <script src="..."> — we record the URL but don't fetch
_RE_EXTERNAL_SCRIPT = re.compile(
    r"<script\b[^>]*\bsrc\s*=\s*[\"\']([^\"\']+)[\"\']",
    re.IGNORECASE,
)


def extract_inline_scripts(html: str) -> List[Tuple[str, int]]:
    """Find all inline <script> blocks. Returns list of (script_body, line).

    Line is 1-based line number where the script starts.
    """
    if not html:
        return []
    out = []
    for m in _RE_INLINE_SCRIPT.finditer(html):
        body = m.group(1)
        if not body.strip():
            continue
        # Find line number of script start
        line = html.count("\n", 0, m.start()) + 1
        out.append((body, line))
    return out


def extract_external_script_urls(html: str, base_url: str = "") -> List[str]:
    """Find all <script src="..."> URLs. Resolves relative to base_url
    if provided."""
    if not html:
        return []
    urls = []
    for m in _RE_EXTERNAL_SCRIPT.finditer(html):
        src = m.group(1)
        if base_url:
            try:
                from urllib.parse import urljoin
                src = urljoin(base_url, src)
            except Exception:
                pass
        urls.append(src)
    return urls


def analyze_html_inline_scripts(html: str,
                                  page_url: str = "") -> List[StaticFinding]:
    """Extract all inline <script> blocks from html and analyze each.

    Returns combined list of findings, with file= page_url and
    line offset adjusted to the position in the HTML.
    """
    if not html:
        return []
    all_findings: List[StaticFinding] = []
    for script_body, html_line in extract_inline_scripts(html):
        findings = analyze_js_source(script_body,
                                       source_name=page_url or "<inline>")
        # Adjust line numbers to be relative to the HTML, not the script
        for f in findings:
            f.line = (f.line or 0) + html_line - 1
        all_findings.extend(findings)
    return all_findings
