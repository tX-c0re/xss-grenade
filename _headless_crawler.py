"""
_headless_crawler.py — sofistikovaný headless-driven authenticated crawler (v10.46)

Crawler na úroveň 2026: nečte statické HTML, ale prochází REÁLNĚ vyrenderovaný
DOM v Chromiu — takže vidí JS-renderované odkazy, SPA routy, dynamicky vložené
formuláře a XHR/fetch API plochu, které statický crawler míjí. Plus autentizace:
form-login, storage_state replay (cookies+localStorage) a re-auth při ztrátě
session.

Výstup (CrawlResult) se mapuje na to, co scan fáze čekají:
  - pages:         vyrenderované stránky (pro page-based skeny)
  - param_urls:    URL s query parametry (pro reflected/context skeny)
  - forms:         formuláře z živého DOM (pro stored/form skeny)
  - api_endpoints: zachycené XHR/fetch (method/url/params/body-keys/ct)

Návrh: jeden authenticated browser context na celý crawl (session persistuje).
BFS s normalizací URL, dedup, scope a trap-guardem. Klikání (bounded) odhalí
SPA navigaci přes history.pushState / hash routy.

Browser (už spuštěný Playwright sync Browser) se PŘEDÁVÁ — modul je decoupled
a testovatelný samostatně.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urljoin, parse_qs
import re


@dataclass
class CrawlConfig:
    max_depth: int = 3
    max_pages: int = 200
    same_origin_only: bool = True
    allowed_hosts: Set[str] = field(default_factory=set)
    nav_timeout_s: float = 15.0
    settle_ms: int = 800          # čekání po načtení na doběh JS
    network_idle: bool = True     # zkus počkat na network-idle (best-effort)
    click_interactions: bool = True
    max_clicks_per_page: int = 6  # kolik in-page prvků kliknout (odhal SPA routy)
    capture_xhr: bool = True
    max_param_urls: int = 500


@dataclass
class AuthConfig:
    # A) storage_state (cookies + localStorage), zaznamenané externě
    storage_state: Optional[dict] = None
    # B) form login
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    username_selector: Optional[str] = None   # auto-detekce když None
    password_selector: Optional[str] = None
    submit_selector: Optional[str] = None
    # validita session
    logged_in_selector: Optional[str] = None  # přítomnost = přihlášeno
    logged_in_text: Optional[str] = None      # text v DOM = přihlášeno
    extra_headers: Optional[Dict[str, str]] = None  # např. Bearer token
    # bezpečnost crawlu
    logout_patterns: List[str] = field(default_factory=lambda: [
        "logout", "signout", "sign-out", "log-out", "odhlasit", "odhlaseni"])

    @property
    def has_form_login(self) -> bool:
        return bool(self.login_url and self.username is not None
                    and self.password is not None)


@dataclass
class DiscoveredForm:
    url: str
    action: str
    method: str
    inputs: List[Dict[str, str]]


@dataclass
class ApiEndpoint:
    method: str
    url: str
    content_type: str
    body_keys: List[str]
    resource_type: str


@dataclass
class CrawlResult:
    pages: List[str] = field(default_factory=list)
    param_urls: List[str] = field(default_factory=list)
    forms: List[DiscoveredForm] = field(default_factory=list)
    api_endpoints: List[ApiEndpoint] = field(default_factory=list)
    cookies: List[Dict] = field(default_factory=list)  # session cookies po crawlu
    auth_ok: bool = False
    auth_method: str = "none"


# ── URL helpers ────────────────────────────────────────────────────────────
# v10.77: hash-mode SPA routes (#/admin, #!/login, #/search?q=x) must survive
# normalization/dedup — the old code split on '#' everywhere, collapsing EVERY
# hash route to the origin root, so after the first page every further route was
# skipped (a DOM-XSS false negative for location.hash sinks). We preserve a
# fragment only when it looks like a ROUTE (starts with /, !/, or carries its own
# path/query/params); plain anchors (#section) still collapse for dedup.
_HASH_ROUTE_RX = re.compile(r"^!?/")   # '/admin' or '!/admin' after the '#'


def _is_route_frag(fragment: str) -> bool:
    return bool(fragment) and (_HASH_ROUTE_RX.match(fragment) is not None
                               or "/" in fragment or "?" in fragment or "=" in fragment)


def _keep_route(url: str) -> str:
    """Strip plain #anchors but PRESERVE hash-route fragments."""
    base, _, frag = url.partition("#")
    return (base + "#" + frag) if _is_route_frag(frag) else base


def normalize_url(url: str, drop_query: bool = False) -> str:
    """Kanonikalizace pro dedup: lowercase host, bez default portu, seřazené
    query, bez koncového /. Route-like fragment (#/... SPA route) se ZACHOVÁ,
    plain #anchor se zahodí. drop_query → jen scheme+host+path."""
    try:
        p = urlsplit(url)
    except Exception:
        return url
    scheme = (p.scheme or "http").lower()
    host = (p.hostname or "").lower()
    # v10.77: `.port` raises ValueError on an out-of-range/non-numeric port; it
    # sat OUTSIDE the try above, so a malformed-port DOM link crashed the crawl.
    try:
        port = p.port
    except ValueError:
        port = None
    if port and not ((scheme == "http" and port == 80) or
                     (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    else:
        netloc = host
    path = re.sub(r"/+", "/", p.path or "/")
    if len(path) > 1:
        path = path.rstrip("/")
    query = ""
    if not drop_query and p.query:
        query = "&".join(f"{k}={v}" for k, v in sorted(parse_qsl(p.query, keep_blank_values=True)))
    # keep a route-like fragment in the dedup key so #/admin ≠ #/login ≠ root
    frag = p.fragment if (not drop_query and _is_route_frag(p.fragment)) else ""
    return urlunsplit((scheme, netloc, path, query, frag))


def path_signature(url: str) -> str:
    """Signatura endpointu pro trap-guard: path + seřazené KLÍČE query (bez
    hodnot). /search?q=a a /search?q=b → stejná signatura."""
    try:
        p = urlsplit(url)
        keys = sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)})
        return f"{(p.hostname or '').lower()}{p.path}?{','.join(keys)}"
    except Exception:
        return url


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


class HeadlessCrawler:
    """Authenticated headless crawler. browser = spuštěný Playwright sync Browser."""

    def __init__(self, browser: Any, config: Optional[CrawlConfig] = None,
                 auth: Optional[AuthConfig] = None,
                 on_log: Optional[Callable[[str, str], None]] = None,
                 cancel_check: Optional[Callable[[], bool]] = None):
        self.browser = browser
        self.cfg = config or CrawlConfig()
        self.auth = auth or AuthConfig()
        self._log = on_log or (lambda m, l="info": None)
        self._cancelled = cancel_check or (lambda: False)
        self._ctx = None
        self._xhr: Dict[str, ApiEndpoint] = {}
        self._scope_hosts: Set[str] = set()

    @property
    def available(self) -> bool:
        return self.browser is not None

    # ── scope ──────────────────────────────────────────────────────────────
    def _in_scope(self, url: str) -> bool:
        if not url.startswith(("http://", "https://")):
            return False
        h = _host_of(url)
        if not h:
            return False
        if self.auth.logout_patterns and any(
                pat in url.lower() for pat in self.auth.logout_patterns):
            return False
        if not self.cfg.same_origin_only:
            return True
        return h in self._scope_hosts or h in {x.lower() for x in self.cfg.allowed_hosts}

    # ── context + auth ─────────────────────────────────────────────────────
    def _new_context(self):
        kwargs = {"ignore_https_errors": True, "java_script_enabled": True}
        if self.auth.storage_state:
            kwargs["storage_state"] = self.auth.storage_state
        ctx = self.browser.new_context(**kwargs)
        if self.auth.extra_headers:
            try: ctx.set_extra_http_headers(self.auth.extra_headers)
            except Exception: pass
        if self.cfg.capture_xhr:
            ctx.on("request", self._on_request)
        return ctx

    def _on_request(self, request):
        try:
            rtype = request.resource_type
            if rtype not in ("xhr", "fetch"):
                return
            url = request.url
            method = (request.method or "GET").upper()
            body_keys: List[str] = []
            ct = ""
            try:
                hdrs = request.headers or {}
                ct = hdrs.get("content-type", "")
            except Exception:
                pass
            try:
                pd = request.post_data
                if pd:
                    if "json" in ct.lower() or pd.strip().startswith("{"):
                        import json
                        try:
                            obj = json.loads(pd)
                            if isinstance(obj, dict):
                                body_keys = list(obj.keys())
                        except Exception:
                            pass
                    else:
                        body_keys = [k for k, _ in parse_qsl(pd, keep_blank_values=True)]
            except Exception:
                pass
            key = f"{method} {normalize_url(url)} {','.join(sorted(body_keys))}"
            if key not in self._xhr:
                self._xhr[key] = ApiEndpoint(method=method, url=url,
                                             content_type=ct, body_keys=body_keys,
                                             resource_type=rtype)
        except Exception:
            pass

    def _settle(self, page):
        if self.cfg.network_idle:
            try:
                page.wait_for_load_state("networkidle",
                                         timeout=min(5000, int(self.cfg.nav_timeout_s * 1000)))
            except Exception:
                pass
        if self.cfg.settle_ms > 0:
            try: page.wait_for_timeout(self.cfg.settle_ms)
            except Exception: pass

    def _looks_logged_in(self, page) -> bool:
        try:
            if self.auth.logged_in_selector:
                return page.query_selector(self.auth.logged_in_selector) is not None
            if self.auth.logged_in_text:
                txt = page.content() or ""
                return self.auth.logged_in_text.lower() in txt.lower()
            # heuristika: password input mimo login_url ⇒ nejspíš odhlášeno
            if self.auth.login_url and normalize_url(page.url, True) != normalize_url(self.auth.login_url, True):
                return page.query_selector("input[type=password]") is None
        except Exception:
            pass
        return True

    def _do_form_login(self, page) -> bool:
        """Vyplní a odešle login formulář. Auto-detekce polí když nejsou zadané."""
        a = self.auth
        try:
            page.goto(a.login_url, wait_until="domcontentloaded",
                      timeout=self.cfg.nav_timeout_s * 1000)
            self._settle(page)
            # password field
            psel = a.password_selector or "input[type=password]"
            pwd = page.query_selector(psel)
            if pwd is None:
                self._log("[CRAWL-AUTH] login: password pole nenalezeno", "warn")
                return False
            # username field: zadané, nebo první text/email input před password
            usel = a.username_selector
            if usel:
                usr = page.query_selector(usel)
            else:
                usr = None
                cands = page.query_selector_all(
                    "input[type=text], input[type=email], input[name], input:not([type])")
                for c in cands:
                    try:
                        t = (c.get_attribute("type") or "text").lower()
                        if t in ("text", "email", ""):
                            usr = c
                            break
                    except Exception:
                        continue
            if usr is not None:
                usr.fill(a.username)
            pwd.fill(a.password)
            # submit
            ssel = a.submit_selector or "button[type=submit], input[type=submit], button"
            btn = page.query_selector(ssel)
            if btn is not None:
                btn.click()
            else:
                pwd.press("Enter")
            self._settle(page)
            ok = self._looks_logged_in(page)
            self._log(f"[CRAWL-AUTH] form-login {'OK' if ok else 'NEPOTVRZENO'} "
                      f"({a.username}@{a.login_url})", "info" if ok else "warn")
            return ok
        except Exception as e:
            self._log(f"[CRAWL-AUTH] login chyba: {e}", "warn")
            return False

    def _ensure_authed(self, page) -> bool:
        if not self.auth.has_form_login:
            return True
        if self._looks_logged_in(page):
            return True
        self._log("[CRAWL-AUTH] session ztracena → re-login", "warn")
        return self._do_form_login(page)

    # ── extrakce z živého DOM ────────────────────────────────────────────────
    def _extract_links(self, page) -> List[str]:
        out: List[str] = []
        try:
            for frame in page.frames:
                try:
                    hrefs = frame.eval_on_selector_all(
                        "a[href]", "els => els.map(e => e.href)")
                except Exception:
                    hrefs = []
                base = frame.url
                for h in (hrefs or []):
                    try:
                        absu = urljoin(base, h)
                        if absu.startswith(("http://", "https://")):
                            out.append(_keep_route(absu))   # keep #/spa-routes
                    except Exception:
                        continue
        except Exception:
            pass
        return out

    def _extract_forms(self, page) -> List[DiscoveredForm]:
        forms: List[DiscoveredForm] = []
        try:
            for frame in page.frames:
                try:
                    # Deep-query forms across OPEN shadow roots (Web Components).
                    # eval_on_selector_all uses the light-DOM selector engine, so
                    # forms inside custom elements were invisible to the crawler.
                    raw = frame.evaluate("""() => {
                        function dqa(sel, root){ root=root||document; var out=[];
                          try{ root.querySelectorAll(sel).forEach(function(e){out.push(e);});
                            root.querySelectorAll('*').forEach(function(e){ if(e.shadowRoot)
                              dqa(sel,e.shadowRoot).forEach(function(n){out.push(n);}); }); }catch(e){}
                          return out; }
                        return dqa('form').map(function(f){ return {
                            action: f.action || '',
                            method: (f.method || 'get'),
                            inputs: dqa('input,textarea,select', f).map(function(i){ return {
                                name: i.name || '', type: (i.type || 'text'), value: i.value || ''
                            }; })
                        }; });
                    }""")
                except Exception:
                    raw = []
                for f in (raw or []):
                    forms.append(DiscoveredForm(
                        url=frame.url, action=f.get("action") or frame.url,
                        method=(f.get("method") or "get").upper(),
                        inputs=f.get("inputs") or []))
        except Exception:
            pass
        return forms

    def _click_to_reveal(self, page) -> List[str]:
        """Bounded klikání na in-page prvky (buttony, [role=button], [data-*]
        togglery) → odhalí SPA routy přes history.pushState / nově vložené <a>.
        Po případné navigaci se vrátí zpět."""
        revealed: List[str] = []
        if not self.cfg.click_interactions:
            return revealed
        try:
            start_url = page.url
            sels = ("button:not([type=submit]), [role=button], [onclick], "
                    "[data-toggle], [data-target], summary, [aria-haspopup]")
            handles = page.query_selector_all(sels)[:self.cfg.max_clicks_per_page]
            for h in handles:
                if self._cancelled():
                    break
                try:
                    h.click(timeout=1500)
                except Exception:
                    continue
                try: page.wait_for_timeout(250)
                except Exception: pass
                # nové odkazy + změna URL (pushState/hash route)
                revealed.extend(self._extract_links(page))
                cur = page.url
                if normalize_url(cur) != normalize_url(start_url):
                    revealed.append(_keep_route(cur))   # keep #/spa-routes
                    try:
                        page.go_back(wait_until="domcontentloaded", timeout=4000)
                        self._settle(page)
                    except Exception:
                        try:
                            page.goto(start_url, wait_until="domcontentloaded",
                                      timeout=self.cfg.nav_timeout_s * 1000)
                            self._settle(page)
                        except Exception:
                            break
        except Exception:
            pass
        return revealed

    # ── hlavní crawl ─────────────────────────────────────────────────────────
    def crawl(self, seed_urls: List[str]) -> CrawlResult:
        result = CrawlResult()
        if not self.available or not seed_urls:
            return result
        seeds = [s for s in seed_urls if s and s.startswith(("http://", "https://"))]
        if not seeds:
            return result
        self._scope_hosts = {_host_of(s) for s in seeds if _host_of(s)}
        if self.auth.login_url:
            h = _host_of(self.auth.login_url)
            if h:
                self._scope_hosts.add(h)

        self._ctx = self._new_context()
        page = self._ctx.new_page()
        page.set_default_timeout(self.cfg.nav_timeout_s * 1000)

        # autentizace
        if self.auth.storage_state:
            result.auth_method = "storage_state"
            result.auth_ok = True
        if self.auth.has_form_login:
            if self._do_form_login(page):
                result.auth_ok = True
                result.auth_method = "form_login" if result.auth_method == "none" else result.auth_method
            else:
                self._log("[CRAWL-AUTH] login selhal — crawl pokračuje neautentizovaně", "warn")

        visited: Set[str] = set()
        sig_count: Dict[str, int] = {}
        forms_seen: Set[str] = set()
        queue: List[Tuple[str, int]] = [(s, 0) for s in seeds]

        while queue and len(result.pages) < self.cfg.max_pages:
            if self._cancelled():
                break
            url, depth = queue.pop(0)
            nu = normalize_url(url)
            if nu in visited or depth > self.cfg.max_depth:
                continue
            visited.add(nu)
            # trap-guard: max 5 stránek na endpoint-signaturu
            sig = path_signature(url)
            sig_count[sig] = sig_count.get(sig, 0) + 1
            if sig_count[sig] > 5:
                continue
            try:
                page.goto(url, wait_until="domcontentloaded",
                          timeout=self.cfg.nav_timeout_s * 1000)
            except Exception:
                continue
            self._settle(page)
            self._ensure_authed(page)

            result.pages.append(page.url.split("#")[0])
            # param URL?
            if urlsplit(page.url).query and len(result.param_urls) < self.cfg.max_param_urls:
                result.param_urls.append(page.url.split("#")[0])

            # formuláře
            for fm in self._extract_forms(page):
                fk = normalize_url(fm.action) + "|" + ",".join(
                    i.get("name", "") for i in fm.inputs)
                if fk not in forms_seen:
                    forms_seen.add(fk)
                    result.forms.append(fm)

            # odkazy z DOM + klikání
            links = self._extract_links(page)
            links.extend(self._click_to_reveal(page))
            for lk in links:
                if not self._in_scope(lk):
                    continue
                nlk = normalize_url(lk)
                if nlk in visited:
                    # i tak zaznamenej param URL pro sken (jiné hodnoty)
                    if urlsplit(lk).query and len(result.param_urls) < self.cfg.max_param_urls:
                        if lk.split("#")[0] not in result.param_urls:
                            result.param_urls.append(lk.split("#")[0])
                    continue
                if depth + 1 <= self.cfg.max_depth:
                    queue.append((lk, depth + 1))
                if urlsplit(lk).query and len(result.param_urls) < self.cfg.max_param_urls:
                    if lk.split("#")[0] not in result.param_urls:
                        result.param_urls.append(lk.split("#")[0])

        # XHR/fetch API plocha
        result.api_endpoints = list(self._xhr.values())
        # param URL i z GET XHR
        for ep in result.api_endpoints:
            if ep.method == "GET" and urlsplit(ep.url).query:
                u = ep.url.split("#")[0]
                if u not in result.param_urls and len(result.param_urls) < self.cfg.max_param_urls:
                    result.param_urls.append(u)

        # session cookies (pro propsání do HTTP scan fází)
        try:
            result.cookies = self._ctx.cookies()
        except Exception:
            result.cookies = []

        try: page.close()
        except Exception: pass
        try: self._ctx.close()
        except Exception: pass

        self._log(f"[CRAWL] hotovo: {len(result.pages)} stránek, "
                  f"{len(result.param_urls)} param URL, {len(result.forms)} formulářů, "
                  f"{len(result.api_endpoints)} API endpointů "
                  f"(auth={result.auth_method}/{result.auth_ok})", "info")
        return result
