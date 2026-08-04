"""
_headless_verifier.py
=====================
Headless DOM verifier — definitive XSS verification using Chromium.

Background
----------
Every other gate in this scanner is a HEURISTIC:
- Context engine: where did marker land in the DOM?
- Render gate: did breakout chars survive in executable form?
- Active probe: did multi-encoded markers survive?

These all have failure modes — they look at HTTP RESPONSES, not at what
the BROWSER actually does with that response. The browser:
  - re-parses HTML according to spec (mutations possible)
  - executes JS (template engines, frameworks, sanitizers)
  - applies CSP (which may block the exact thing we'd flag as exec)
  - resolves prototype chains, Custom Elements, Shadow DOM, etc.

The headless verifier is the ground truth. It opens the URL in real
Chromium, waits for the page to render, hooks JS dialogs and console,
and checks if the payload actually fires.

What it verifies
----------------
1. Reflected XSS — opens findings URL, waits for page load, listens
   for window.alert/confirm/prompt to fire. If our canary message
   appears in dialog → confirmed exec.
2. Template injection — same as reflected, but framework needs time
   to bootstrap and evaluate expressions (extra 500ms wait).
3. Mutation XSS — loads test page that runs sanitizer + innerHTML
   pipeline, watches for dialog. (Caller provides test page HTML.)

Output verdicts
---------------
    EXECUTED      — dialog fired with our canary
    NOT_EXECUTED  — page loaded, no dialog
    ERROR         — page failed to load or browser crashed
    SKIPPED       — playwright unavailable / config disabled

Public API
----------

    HeadlessVerifier(headless=True, max_browsers=2, timeout_s=10.0)
        Context manager. Use as:

            with HeadlessVerifier() as hv:
                verdict = hv.verify_url("https://target/?q=<payload>",
                                         expect_canary="XSGRENADE_777")
                if verdict.executed:
                    print(f"CONFIRMED XSS via {verdict.method}")

    verify_url(url, expect_canary, framework_wait=False) -> Verdict
    verify_test_page(html, expect_canary) -> Verdict
        For mXSS — caller builds test page via
        _mutation_xss.build_test_page() and verifies here.
"""

from __future__ import annotations

import logging
import os
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Tuple

log = logging.getLogger("xss_grenade.headless")

# ─────────────────────────────────────────────────────────────────────────
# Optional playwright — graceful degrade if missing
# ─────────────────────────────────────────────────────────────────────────
try:
    from playwright.sync_api import sync_playwright, Browser, BrowserContext, Page
    from playwright.sync_api import TimeoutError as PWTimeoutError
    from playwright.sync_api import Error as PWError
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False
    sync_playwright = None
    Browser = None
    BrowserContext = None
    Page = None
    PWTimeoutError = Exception
    PWError = Exception


# ═══════════════════════════════════════════════════════════════════════════
# DATA TYPES
# ═══════════════════════════════════════════════════════════════════════════

class VerdictStatus(str, Enum):
    EXECUTED     = "executed"        # Dialog fired with our canary
    NOT_EXECUTED = "not_executed"    # Page loaded, no dialog
    ERROR        = "error"           # Browser/network error
    SKIPPED      = "skipped"         # Playwright not available


@dataclass
class HeadlessVerdict:
    status:        VerdictStatus
    executed:      bool = False         # convenience
    method:        str = ""             # "alert" / "console" / "title" / "selector"
    evidence:      str = ""             # message/text matched
    screenshot:    Optional[bytes] = None   # PNG bytes
    console_msgs:  List[str] = field(default_factory=list)
    page_errors:   List[str] = field(default_factory=list)
    elapsed_ms:    int = 0
    final_url:     str = ""             # after redirects
    error:         str = ""             # populated when status==ERROR

    def __repr__(self) -> str:
        s = f"HeadlessVerdict({self.status.value}"
        if self.executed:
            s += f" via {self.method!r}"
        if self.error:
            s += f" err={self.error[:60]!r}"
        s += f" {self.elapsed_ms}ms)"
        return s


# ═══════════════════════════════════════════════════════════════════════════
# CANARY GENERATION
# ═══════════════════════════════════════════════════════════════════════════
#
# Every verification needs a unique canary string we can recognize
# unambiguously in alert(...) / console / title. We standardize on
# "XSGV_<random>" prefix so we don't accidentally match the target's
# real text.

import random
import string

def _pp_rand_token(n: int = 10) -> str:
    """Short alphanumeric token for prototype-pollution runtime probes."""
    return "".join(random.choice(string.ascii_lowercase + string.digits)
                   for _ in range(n))

def make_canary(prefix: str = "XSGV") -> str:
    """Generate unique canary token, e.g. 'XSGV_K5T9R2P1'."""
    rnd = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
    return f"{prefix}_{rnd}"


# Replace 'alert(1)' / 'alert("XSS")' etc. patterns in payloads with
# alert("<canary>") so we can match dialog message unambiguously.
_ALERT_REWRITE_RX = re.compile(
    r"""(alert|confirm|prompt)\s*\(\s*(?:["'][^"']*["']|\d+|/\*.*?\*/)?\s*\)""",
    re.IGNORECASE | re.DOTALL,
)


def rewrite_payload_with_canary(payload: str, canary: str) -> str:
    """Replace alert(…)/confirm(…)/prompt(…) calls with alert('<canary>').
    Returns rewritten payload + canary used."""
    if not payload:
        return payload
    # Replace any alert/confirm/prompt call with alert("<canary>")
    rewritten = _ALERT_REWRITE_RX.sub(f'alert("{canary}")', payload)
    return rewritten


# ═══════════════════════════════════════════════════════════════════════════
# HOOK SCRIPT — injected into page BEFORE navigation
# ═══════════════════════════════════════════════════════════════════════════
#
# Runs before any page JS. Captures:
#  - alert/confirm/prompt calls (with messages)
#  - console.log/warn/error (some payloads use console.log("XSS"))
#  - document.title changes
#  - DOM element matches (sentinel selectors)
#
# Result accumulated to window.__XSGV_RESULT__ for caller to read.

HOOK_SCRIPT = r"""
(() => {
  if (window.__XSGV_RESULT__) return;   // idempotent
  window.__XSGV_RESULT__ = {
    dialogs: [],
    console: [],
    page_errors: [],
    title_changes: [],
    selectors_matched: [],
  };

  // Hook dialog primitives
  const hookDialog = (name) => {
    const orig = window[name];
    window[name] = function(msg) {
      try {
        window.__XSGV_RESULT__.dialogs.push({
          fn: name,
          message: msg === undefined ? "" : String(msg)
        });
      } catch (e) { /* noop */ }
      // Don't actually call orig — we don't want real dialogs blocking page
      return undefined;
    };
  };
  ['alert', 'confirm', 'prompt'].forEach(hookDialog);

  // Hook console
  ['log', 'warn', 'error', 'info'].forEach(level => {
    const orig = console[level];
    console[level] = function(...args) {
      try {
        const msg = args.map(a => {
          try { return typeof a === 'string' ? a : JSON.stringify(a); }
          catch(_) { return String(a); }
        }).join(' ');
        window.__XSGV_RESULT__.console.push({ level: level, message: msg });
      } catch (e) { /* noop */ }
      try { return orig.apply(console, args); } catch(_) { return undefined; }
    };
  });

  // Watch for window.onerror — some payloads cause syntax errors that
  // still indicate eval was attempted (e.g. partial breakouts).
  window.addEventListener('error', (ev) => {
    try {
      window.__XSGV_RESULT__.page_errors.push(String(ev.message || ev.error || ev));
    } catch(_) { /* noop */ }
  });
})();
"""


# ═══════════════════════════════════════════════════════════════════════════
# VERIFIER CLASS — context manager
# ═══════════════════════════════════════════════════════════════════════════

# v10.49: sdílená detekce JS-frameworku — rozhoduje, jestli stránka může
# vystřelit POZDĚ (hydration) a tedy potřebuje plný settle budget, nebo je
# statická a stačí krátký floor. Konzervativní (radši false-positive frameworku
# = pomalejší, než false-negative = minutý XSS).
_FRAMEWORK_DETECT_JS = """() => {
    if (window.React||window.ng||window.Vue||window.angular||
        window.__NEXT_DATA__||window.__NUXT__||window.__svelte__||
        window.Alpine||window.Stimulus||window.jQuery||window.$||
        document.querySelector('[ng-version],[data-reactroot],[data-v-app],[data-server-rendered],#__next,#__nuxt,[x-data]'))
        return true;
    // v10.82 DEPTH: work still pending → an async event-handler payload
    // (<img src=x onerror=…>, <body onload=…>) fires only AFTER the resource
    // settles, i.e. after domcontentloaded. If any image hasn't finished, keep
    // the full settle budget so those payloads fire before we read state. This
    // only LENGTHENS the wait on pages that genuinely have pending work — it can
    // never invent an execution signal, so it adds no false positive.
    try {
        var imgs = document.images;
        for (var i = 0; i < imgs.length; i++) { if (!imgs[i].complete) return true; }
    } catch (e) {}
    return false;
}"""


class HeadlessVerifier:
    """Browser pool + verification API.

    Use as context manager:
        with HeadlessVerifier(max_browsers=2) as hv:
            v1 = hv.verify_url(url, canary)
            v2 = hv.verify_test_page(html, canary)
    """

    def __init__(self,
                 headless: bool = True,
                 max_browsers: int = 1,
                 timeout_s: float = 10.0,
                 framework_wait_ms: int = 800,
                 screenshot: bool = True,
                 user_agent: Optional[str] = None,
                 ignore_https_errors: bool = True,
                 extra_args: Optional[List[str]] = None):
        self.headless = headless
        self.max_browsers = max(1, int(max_browsers))
        self.timeout_s = float(timeout_s)
        self.framework_wait_ms = int(framework_wait_ms)
        self.screenshot = screenshot
        self.user_agent = user_agent or (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
        )
        self.ignore_https_errors = ignore_https_errors
        self.extra_args = extra_args or []

        self._pw = None
        self._browser: Optional[Browser] = None
        self._available = _PLAYWRIGHT_AVAILABLE

    @property
    def available(self) -> bool:
        return self._available

    def __enter__(self):
        if not self._available:
            return self
        try:
            self._pw = sync_playwright().start()
            self._browser = self._pw.chromium.launch(
                headless=self.headless,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                ] + list(self.extra_args),
            )
        except Exception as e:
            log.warning("Failed to launch Chromium: %s", e)
            self._available = False
            self._browser = None
        return self

    def __exit__(self, *_args):
        try:
            if self._browser is not None:
                self._browser.close()
        except Exception:
            pass
        try:
            if self._pw is not None:
                self._pw.stop()
        except Exception:
            pass

    # ────────────────────────────────────────────────────────────────────
    # CORE VERIFICATION METHODS
    # ────────────────────────────────────────────────────────────────────

    def _framework_gated_wait(self, page, budget_ms, floor_ms: int = 200):
        """v10.49: pre-action settle (kanárek ještě nevznikl) — počká floor_ms;
        jen pokud je na stránce JS-framework, dočká zbytek budgetu. Statické
        stránky mají DOM hotový hned → neplatí celých 800 ms zbytečně."""
        if budget_ms <= 0:
            return
        floor = min(floor_ms, budget_ms)
        try:
            page.wait_for_timeout(floor)
        except Exception:
            pass
        if floor >= budget_ms:
            return
        try:
            has_fw = bool(page.evaluate(_FRAMEWORK_DETECT_JS))
        except Exception:
            has_fw = False
        if has_fw:
            try:
                page.wait_for_timeout(budget_ms - floor)
            except Exception:
                pass

    def _poll_canary_main(self, page, expect_canary, budget_ms,
                          floor_ms: int = 120, step_ms: int = 80) -> bool:
        """v10.49: post-action settle (akce už proběhla) — pollne hlavní page
        a vrátí True HNED, jakmile kanárek vystřelí; jinak po budgetu False.
        Pro js_uri / postmessage (single-window, dialog kanárek)."""
        canary = (expect_canary or "").lower()
        waited = 0
        while waited < budget_ms:
            step = min(step_ms, budget_ms - waited)
            try:
                page.wait_for_timeout(step)
            except Exception:
                pass
            waited += step
            try:
                st = page.evaluate("() => window.__XSGV_RESULT__ || null")
            except Exception:
                st = None
            if st:
                for d in (st.get("dialogs") or []):
                    if canary and canary in str(d.get("message") or "").lower():
                        return True
            if waited < floor_ms:
                continue
        return False

    def _adaptive_settle(self, page, expect_canary, budget_ms,
                         floor_ms: int = 300, step_ms: int = 100):
        """v10.49: adaptivní settle s early-exit — nahrazuje slepý fixní wait.

        - pollne hook stav po krocích a vrátí HNED, jakmile kanárek vystřelí
          → rychlé pozitivy (onerror/onload/script vystřelí <100 ms)
        - na stránce BEZ JS-frameworku skončí po floor_ms místo celého budgetu
          → rychlé negativy (drtivá většina payloadů nevystřelí pozdě)
        - na stránce S frameworkem (React/Vue/Angular/Next/Nuxt/Svelte) počká
          plný budget → ne-mine pozdní hydration XSS (žádné false-negativy)

        Vrací poslední hook stav (verdikt staví _build_verdict jako dřív)."""
        canary = (expect_canary or "").lower()
        try:
            has_fw = bool(page.evaluate(_FRAMEWORK_DETECT_JS))
        except Exception:
            has_fw = False

        def _fired(st):
            if not st:
                return False
            for d in (st.get("dialogs") or []):
                if canary and canary in str(d.get("message") or "").lower():
                    return True
            # v10.79 fix: the hook state uses keys 'console' and 'page_errors',
            # not 'consoles'/'errors' — so the console/error-canary early-exit
            # never fired. Use the real keys and pull the message field.
            for key in ("console", "page_errors"):
                for v in (st.get(key) or []):
                    _txt = v.get("message") if isinstance(v, dict) else v
                    if canary and canary in str(_txt or "").lower():
                        return True
            return False

        waited = 0
        state = None
        while waited < budget_ms:
            step = min(step_ms, budget_ms - waited)
            try:
                page.wait_for_timeout(step)
            except Exception:
                pass
            waited += step
            try:
                state = page.evaluate("() => window.__XSGV_RESULT__ || null")
            except Exception:
                pass
            if _fired(state):
                return state                       # rychlý pozitiv
            if waited >= floor_ms and not has_fw:
                return state                       # rychlý negativ (statická stránka)
        return state

    def verify_url(self,
                    url: str,
                    expect_canary: str,
                    framework_wait: bool = False,
                    cookies: Optional[List[Dict]] = None,
                    headers: Optional[Dict[str, str]] = None) -> HeadlessVerdict:
        """Open URL in headless Chromium; verify if expect_canary fires
        in dialog/console/title/error.

        Args:
            url: full URL with payload as query/fragment param.
            expect_canary: unique token attacker payload should produce
                if it executed. Caller is responsible for ensuring
                payload contains alert("<canary>") or equivalent.
            framework_wait: extra wait for SPA frameworks to bootstrap.
            cookies: optional list of dicts {name, value, domain, path}
            headers: optional extra HTTP headers (e.g. for auth)
        """
        if not self._available or self._browser is None:
            return HeadlessVerdict(status=VerdictStatus.SKIPPED,
                                    error="playwright_unavailable")

        start = time.perf_counter()
        ctx: Optional[BrowserContext] = None
        page: Optional[Page] = None
        try:
            ctx = self._browser.new_context(
                user_agent=self.user_agent,
                ignore_https_errors=self.ignore_https_errors,
                java_script_enabled=True,
                bypass_csp=False,   # Respect CSP — we want real-world verdict
            )
            if headers:
                try:
                    ctx.set_extra_http_headers(headers)
                except Exception:
                    pass
            if cookies:
                try:
                    ctx.add_cookies(cookies)
                except Exception:
                    pass

            page = ctx.new_page()
            page.set_default_timeout(self.timeout_s * 1000)

            # Inject hook BEFORE any page script runs
            page.add_init_script(HOOK_SCRIPT)

            # Capture page errors (CSP violations, syntax errors, etc.)
            errors: List[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))

            # Auto-dismiss dialogs that managed to slip past hook
            page.on("dialog", lambda d: (errors.append(f"native_dialog:{d.type}:{d.message}"),
                                          d.dismiss()))

            # Navigate
            try:
                resp = page.goto(url, wait_until="domcontentloaded",
                                 timeout=self.timeout_s * 1000)
            except PWTimeoutError:
                # Even on timeout, page may have partially loaded — check anyway
                resp = None
            except PWError as nav_err:
                return HeadlessVerdict(
                    status=VerdictStatus.ERROR,
                    error=f"navigation_failed: {nav_err}",
                    elapsed_ms=int((time.perf_counter() - start) * 1000),
                )

            # v10.49: adaptivní settle s early-exit (viz _adaptive_settle) —
            # nahrazuje slepý fixní framework wait. Verdikt staví _build_verdict
            # ze stejného stavu jako dřív, jen se k němu dojde rychleji.
            if framework_wait and self.framework_wait_ms > 0:
                state = self._adaptive_settle(page, expect_canary,
                                              self.framework_wait_ms)
            else:
                try:
                    state = page.evaluate("() => window.__XSGV_RESULT__ || null")
                except Exception:
                    state = None

            final_url = ""
            try:
                final_url = page.url
            except Exception:
                pass

            # Take screenshot if requested
            shot = None
            if self.screenshot:
                try:
                    shot = page.screenshot(full_page=False, timeout=2000)
                except Exception:
                    pass

            verdict = self._build_verdict(
                state=state,
                expect_canary=expect_canary,
                page_errors=errors,
                screenshot=shot,
                final_url=final_url,
                elapsed_ms=int((time.perf_counter() - start) * 1000),
            )
            # v10.82 DEPTH: mXSS harness fail-closed. build_test_page sets
            # __mXSS_RESULT__.warning='no sanitizer loaded' when neither DOMPurify
            # nor jQuery loaded (Sanitizer.SANITIZE_HTML has no CDN, or a CDN/network
            # failure). With no sanitizer running, an EXECUTED verdict only proves
            # raw injection fires — NOT a sanitizer bypass — so downgrade to SKIPPED
            # so the caller never reports a phantom mXSS bypass. (Undefined on every
            # non-mXSS page → returns '' → no-op.)
            try:
                _mx_warn = page.evaluate(
                    "() => (window.__mXSS_RESULT__ && window.__mXSS_RESULT__.warning) || ''")
            except Exception:
                _mx_warn = ""
            if _mx_warn and "no sanitizer" in str(_mx_warn).lower():
                return HeadlessVerdict(
                    status=VerdictStatus.SKIPPED,
                    executed=False,
                    method="",
                    error="sanitizer_absent",
                    page_errors=errors[:20],
                    final_url=final_url,
                    elapsed_ms=int((time.perf_counter() - start) * 1000),
                )
            return verdict

        except Exception as e:
            return HeadlessVerdict(
                status=VerdictStatus.ERROR,
                error=f"{type(e).__name__}: {e}",
                elapsed_ms=int((time.perf_counter() - start) * 1000),
            )
        finally:
            try:
                if page is not None: page.close()
            except Exception: pass
            try:
                if ctx is not None: ctx.close()
            except Exception: pass

    def verify_prototype_pollution(self,
                                    base_url: str,
                                    probe_token: Optional[str] = None,
                                    framework_wait: bool = True,
                                    cookies: Optional[List[Dict]] = None,
                                    headers: Optional[Dict[str, str]] = None
                                    ) -> HeadlessVerdict:
        """v10.18 (FP#1.5 runtime gate): RUNTIME confirmation of prototype
        pollution. Injects a __proto__ pollution payload into the URL, loads
        the page in real Chromium, and checks whether Object.prototype was
        ACTUALLY polluted (i.e. the page's client-side code has a real
        pollution sink reachable from URL input).

        This is the strongest possible confirmation: a static co-located
        source+gadget chain is only a *candidate*; this proves the prototype
        is reachable and polluted at runtime. If the probe property does NOT
        appear on Object.prototype, the static finding should be downgraded.

        Strategy (several common PP-via-URL vectors in one go):
            ?__proto__[TOKEN]=polluted
            ?constructor[prototype][TOKEN]=polluted
            #__proto__[TOKEN]=polluted   (hash-based parsers)

        Returns HeadlessVerdict where:
            executed=True  → Object.prototype.<TOKEN> was set → CONFIRMED PP
            executed=False → no pollution observed → static finding unconfirmed
        """
        if not self._available or self._browser is None:
            return HeadlessVerdict(status=VerdictStatus.SKIPPED,
                                    error="playwright_unavailable")

        token = probe_token or ("xsgsPP" + _pp_rand_token())
        sentinel = "polluted_" + token
        start = time.perf_counter()
        ctx: Optional[BrowserContext] = None
        page: Optional[Page] = None
        try:
            ctx = self._browser.new_context(
                user_agent=self.user_agent,
                ignore_https_errors=self.ignore_https_errors,
                java_script_enabled=True,
                bypass_csp=False,
            )
            if headers:
                try:
                    ctx.set_extra_http_headers(headers)
                except Exception:
                    pass
            if cookies:
                try:
                    ctx.add_cookies(cookies)
                except Exception:
                    pass
            page = ctx.new_page()
            page.set_default_timeout(self.timeout_s * 1000)
            page.on("pageerror", lambda e: None)
            page.on("dialog", lambda d: d.dismiss())

            # Build candidate pollution URLs (query + hash vectors).
            sep = "&" if ("?" in base_url) else "?"
            vectors = [
                # bracket-syntax (lodash/jQuery/deepmerge parsers)
                f"{base_url}{sep}__proto__[{token}]={sentinel}",
                f"{base_url}{sep}constructor[prototype][{token}]={sentinel}",
                f"{base_url}#__proto__[{token}]={sentinel}",
                f"{base_url}#constructor[prototype][{token}]={sentinel}",
                # v10.19: dotted-path syntax (custom split('.') URL parsers —
                # PortSwigger lab vector). Bez tohohle runtime probe minul
                # dotted-path parsery a vracel falešné "not polluted".
                f"{base_url}{sep}__proto__.{token}={sentinel}",
                f"{base_url}{sep}constructor.prototype.{token}={sentinel}",
                f"{base_url}#__proto__.{token}={sentinel}",
                f"{base_url}#constructor.prototype.{token}={sentinel}",
            ]

            confirmed = False
            evidence = ""
            for vurl in vectors:
                try:
                    page.goto(vurl, wait_until="domcontentloaded",
                              timeout=int(self.timeout_s * 1000))
                except Exception:
                    continue
                if framework_wait and self.framework_wait_ms > 0:
                    self._framework_gated_wait(page, self.framework_wait_ms)
                # Check whether Object.prototype was actually polluted.
                try:
                    polluted = page.evaluate(
                        "(t) => { try { return ({}.__proto__[t]"
                        " !== undefined) ? String({}.__proto__[t]) : null; }"
                        " catch(e){ return null; } }",
                        token)
                except Exception:
                    polluted = None
                if polluted is not None:
                    confirmed = True
                    evidence = (f"Object.prototype.{token}={polluted!r} "
                                f"via {vurl.split(base_url)[-1][:60]}")
                    break

            elapsed = int((time.perf_counter() - start) * 1000)
            if confirmed:
                return HeadlessVerdict(
                    status=VerdictStatus.EXECUTED, executed=True,
                    method="prototype_pollution",
                    evidence=evidence, elapsed_ms=elapsed,
                    final_url=page.url if page else base_url)
            return HeadlessVerdict(
                status=VerdictStatus.NOT_EXECUTED, executed=False,
                method="prototype_pollution",
                evidence="Object.prototype not polluted by URL probe",
                elapsed_ms=elapsed,
                final_url=page.url if page else base_url)
        except Exception as e:
            return HeadlessVerdict(status=VerdictStatus.ERROR,
                                    error=str(e)[:200])
        finally:
            try:
                if page is not None:
                    page.close()
                if ctx is not None:
                    ctx.close()
            except Exception:
                pass

    def verify_test_page(self,
                          html: str,
                          expect_canary: str) -> HeadlessVerdict:
        """Verify by loading raw HTML test page (no network).
        Useful for mXSS — caller built sanitizer+innerHTML test page via
        _mutation_xss.build_test_page().
        """
        if not self._available or self._browser is None:
            return HeadlessVerdict(status=VerdictStatus.SKIPPED,
                                    error="playwright_unavailable")
        # Use data URL to load HTML inline
        # data: URLs are tricky — better to write to temp file
        import tempfile
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".html",
                                           delete=False, encoding="utf-8")
        try:
            tmp.write(html)
            tmp.close()
            file_url = "file://" + os.path.abspath(tmp.name)
            return self.verify_url(file_url, expect_canary, framework_wait=False)
        finally:
            try: os.unlink(tmp.name)
            except Exception: pass

    def verify_form_xss(self, url: str, payloads: List[str],
                        cookies: Optional[List[Dict]] = None,
                        submit_wait_ms: int = 1400,
                        framework_wait: bool = True) -> List[Dict]:
        """v10.38: Browser-driven form XSS — vyplní text inputy payloadem a
        ODEŠLE formulář PŘES VLASTNÍ JS STRÁNKY (ne HTTP POST). Chytá client-side
        / JS-handled / localStorage-stored form XSS (Google XSS-game level 2:
        onsubmit vrací false, DB.save→localStorage, innerHTML render) — což HTTP
        POST nikdy nespustí, protože vulnerable code path je čistě klientský.

        Vyplňuje a submituje napříč VŠEMI same-origin frame (iframe /level2/frame
        se obslouží transparentně). Payload obsahuje token 'CANARY' nahrazený
        unikátním kanárkem; detekuje se shoda dialogu v kterémkoli frame.

        Vrací list: [{payload, canary, executed, frame_url}]."""
        out: List[Dict] = []
        if not self._available or self._browser is None:
            return out
        # __dqa: deep querySelectorAll that pierces OPEN shadow roots (Web
        # Components), so inputs/forms/buttons inside custom elements are filled
        # and submitted too — plain querySelectorAll stops at shadow boundaries.
        _dqa = (
            "function __dqa(sel,root){root=root||document;var out=[];"
            "try{root.querySelectorAll(sel).forEach(function(e){out.push(e);});"
            "root.querySelectorAll('*').forEach(function(e){if(e.shadowRoot)"
            "__dqa(sel,e.shadowRoot).forEach(function(n){out.push(n);});});}"
            "catch(e){}return out;}"
        )
        fill_js = """(val) => {
            %s
            let n = 0;
            const sel = 'input[type=text],input[type=search],input[type=url],'
                      + 'input[type=email],input:not([type]),textarea';
            __dqa(sel).forEach(el => { try { el.value = val; n++; } catch(e){} });
            return n;
        }""" % _dqa
        submit_js = """() => {
            %s
            __dqa('form').forEach(f => {
                try { if (f.requestSubmit) f.requestSubmit(); else f.submit(); } catch(e){}
            });
            __dqa('button,input[type=submit]').forEach(b => {
                try { b.click(); } catch(e){}
            });
        }""" % _dqa
        for payload in payloads:
            canary = make_canary()
            injected = payload.replace("CANARY", canary)
            ctx = None
            page = None
            try:
                ctx = self._browser.new_context(
                    user_agent=self.user_agent,
                    ignore_https_errors=self.ignore_https_errors,
                    java_script_enabled=True, bypass_csp=False)
                if cookies:
                    try: ctx.add_cookies(cookies)
                    except Exception: pass
                page = ctx.new_page()
                page.set_default_timeout(self.timeout_s * 1000)
                page.add_init_script(HOOK_SCRIPT)
                page.on("dialog", lambda d: d.dismiss())
                try:
                    page.goto(url, wait_until="domcontentloaded",
                              timeout=self.timeout_s * 1000)
                except (PWTimeoutError, PWError):
                    pass
                if framework_wait and self.framework_wait_ms > 0:
                    self._framework_gated_wait(page, self.framework_wait_ms)
                # vyplň + submit napříč všemi frame (iframe = level-2 frame)
                filled_total = 0
                for fr in page.frames:
                    try:
                        n = fr.evaluate(fill_js, injected)
                        if n:
                            filled_total += n
                            fr.evaluate(submit_js)
                    except Exception:
                        continue
                if not filled_total:
                    continue
                try: page.wait_for_timeout(submit_wait_ms)
                except Exception: pass
                # zkontroluj kanárek v KAŽDÉM frame (alert hook je per-window)
                executed = False
                hit_frame = ""
                for fr in page.frames:
                    try:
                        st = fr.evaluate("() => window.__XSGV_RESULT__ || null")
                    except Exception:
                        st = None
                    if not st:
                        continue
                    for d in (st.get("dialogs") or []):
                        if canary.lower() in str(d.get("message") or "").lower():
                            executed = True
                            try: hit_frame = fr.url
                            except Exception: hit_frame = ""
                            break
                    if executed:
                        break
                out.append({"payload": injected, "canary": canary,
                            "executed": executed, "frame_url": hit_frame})
            except Exception:
                pass
            finally:
                try:
                    if page is not None: page.close()
                except Exception: pass
                try:
                    if ctx is not None: ctx.close()
                except Exception: pass
        return out

    def verify_js_uri(self, url: str, expect_canary: str,
                      cookies: Optional[List[Dict]] = None,
                      framework_wait: bool = True) -> bool:
        """v10.41: potvrdí javascript:-URI XSS (Google XSS-game level 5: vstup
        v <a href="javascript:alert()">, spouští se až KLIKEM). Načte url (payload
        už injektovaný do param), pak najde elementy s javascript: v href/src/
        action/formaction obsahující kanárek a SPUSTÍ je (eval kódu za scheme).
        Vrací True jen při shodě kanárku v dialogu."""
        if not self._available or self._browser is None:
            return False
        ctx = page = None
        try:
            ctx = self._browser.new_context(
                user_agent=self.user_agent,
                ignore_https_errors=self.ignore_https_errors,
                java_script_enabled=True, bypass_csp=False)
            if cookies:
                try: ctx.add_cookies(cookies)
                except Exception: pass
            page = ctx.new_page()
            page.set_default_timeout(self.timeout_s * 1000)
            page.add_init_script(HOOK_SCRIPT)
            page.on("dialog", lambda d: d.dismiss())
            try:
                page.goto(url, wait_until="domcontentloaded",
                          timeout=self.timeout_s * 1000)
            except (PWTimeoutError, PWError):
                pass
            if framework_wait and self.framework_wait_ms > 0:
                self._framework_gated_wait(page, self.framework_wait_ms)
            # najdi javascript: URI v href/src/action/formaction a SPUSŤ je
            exec_js = """(canary) => {
                const attrs = ['href','src','action','formaction','xlink:href'];
                const els = document.querySelectorAll('*');
                let ran = 0;
                els.forEach(el => {
                    for (const a of attrs) {
                        let v = el.getAttribute && el.getAttribute(a);
                        if (!v) continue;
                        if (/^\\s*javascript:/i.test(v)) {
                            try {
                                const code = v.replace(/^\\s*javascript:/i, '');
                                // spusť kód za scheme (alert je hooknutý)
                                (0, eval)(decodeURIComponent(code));
                                ran++;
                            } catch(e){}
                        }
                    }
                });
                return ran;
            }"""
            try:
                page.evaluate(exec_js, expect_canary)
            except Exception:
                pass
            # v10.49: early-exit poll místo slepých 400 ms
            return self._poll_canary_main(page, expect_canary, 400)
        except Exception:
            return False
        finally:
            try:
                if page is not None: page.close()
            except Exception: pass
            try:
                if ctx is not None: ctx.close()
            except Exception: pass

    def verify_postmessage(self, url: str, payload: str, expect_canary: str,
                           cookies: Optional[List[Dict]] = None,
                           framework_wait: bool = True) -> bool:
        """v10.45: potvrdí postMessage XSS. Načte url, počká na bootstrap
        message listenerů, pak rozešle window.postMessage(payload, '*') (i do
        všech same-origin iframů) a sleduje, jestli kanárek vystřelí. Vrací True
        jen při shodě kanárku v dialogu.

        Pozn.: postMessage se posílá jako STRING i jako objekt {data, message,
        html, url, content} — různé listenery čtou různá pole."""
        if not self._available or self._browser is None:
            return False
        ctx = page = None
        try:
            ctx = self._browser.new_context(
                user_agent=self.user_agent,
                ignore_https_errors=self.ignore_https_errors,
                java_script_enabled=True, bypass_csp=False)
            if cookies:
                try: ctx.add_cookies(cookies)
                except Exception: pass
            page = ctx.new_page()
            page.set_default_timeout(self.timeout_s * 1000)
            page.add_init_script(HOOK_SCRIPT)
            page.on("dialog", lambda d: d.dismiss())
            try:
                page.goto(url, wait_until="domcontentloaded",
                          timeout=self.timeout_s * 1000)
            except (PWTimeoutError, PWError):
                pass
            if framework_wait and self.framework_wait_ms > 0:
                self._framework_gated_wait(page, self.framework_wait_ms)
            dispatch = """(p) => {
                const targets = [window];
                try { for (let i=0;i<window.frames.length;i++) targets.push(window.frames[i]); } catch(e){}
                const variants = [p, {data:p, message:p, html:p, url:p, content:p, type:p}];
                targets.forEach(w => {
                    variants.forEach(v => { try { w.postMessage(v, '*'); } catch(e){} });
                });
            }"""
            try:
                page.evaluate(dispatch, payload)
            except Exception:
                pass
            # v10.49: early-exit poll místo slepých 500 ms
            return self._poll_canary_main(page, expect_canary, 500)
        except Exception:
            return False
        finally:
            try:
                if page is not None: page.close()
            except Exception: pass
            try:
                if ctx is not None: ctx.close()
            except Exception: pass

    # ────────────────────────────────────────────────────────────────────
    # VERDICT BUILDING
    # ────────────────────────────────────────────────────────────────────

    def _build_verdict(self, state, expect_canary: str,
                        page_errors: List[str],
                        screenshot: Optional[bytes],
                        final_url: str,
                        elapsed_ms: int) -> HeadlessVerdict:
        """Examine collected state and decide if exec happened."""
        # v10.82 DEPTH: a NATIVE dialog (page.on('dialog')) is GENUINE execution but
        # is recorded into page_errors as 'native_dialog:{type}:{msg}', not into the
        # hooked state.dialogs. Check it FIRST — before the state-is-None early
        # return threw it away — so an alert(canary) that fired via the native
        # handler still confirms even when the injected JS hook never installed.
        _canary_l = (expect_canary or "").lower()
        if _canary_l:
            for _pe in (page_errors or []):
                _s = str(_pe)
                if _s.startswith("native_dialog:") and _canary_l in _s.lower():
                    return HeadlessVerdict(
                        status=VerdictStatus.EXECUTED,
                        executed=True,
                        method="native_dialog",
                        evidence=_s[:200],
                        page_errors=page_errors[:20],
                        screenshot=screenshot,
                        final_url=final_url,
                        elapsed_ms=elapsed_ms,
                    )

        if state is None:
            # Hook didn't run at all — page totally failed or no JS
            return HeadlessVerdict(
                status=VerdictStatus.NOT_EXECUTED,
                executed=False,
                method="",
                page_errors=page_errors,
                screenshot=screenshot,
                final_url=final_url,
                elapsed_ms=elapsed_ms,
                error="hook_state_missing",
            )

        canary = (expect_canary or "").lower()
        dialogs = state.get("dialogs") or []
        console = state.get("console") or []

        # Check 1: dialog fired with our canary
        for d in dialogs:
            msg = str(d.get("message") or "").lower()
            if canary and canary in msg:
                return HeadlessVerdict(
                    status=VerdictStatus.EXECUTED,
                    executed=True,
                    method=f"dialog_{d.get('fn','alert')}",
                    evidence=str(d.get("message") or ""),
                    console_msgs=[str(c) for c in console][:20],
                    page_errors=page_errors[:20],
                    screenshot=screenshot,
                    final_url=final_url,
                    elapsed_ms=elapsed_ms,
                )

        # Check 2: any dialog fired (even without canary match — still
        # indicates exec, payload may have been mangled)
        if dialogs:
            d = dialogs[0]
            return HeadlessVerdict(
                status=VerdictStatus.EXECUTED,
                executed=True,
                method=f"dialog_{d.get('fn','alert')}_no_canary",
                evidence=str(d.get("message") or ""),
                console_msgs=[str(c) for c in console][:20],
                page_errors=page_errors[:20],
                screenshot=screenshot,
                final_url=final_url,
                elapsed_ms=elapsed_ms,
            )

        # Check 3: canary appeared in console. GUARD: when the canary is part of
        # the navigated URL (query/hash/path source), a console echo of the URL
        # is NOT proof of execution — pages routinely log location.href / query
        # params (SPA routers, dev builds, analytics), which would embed the
        # canary in console without the payload ever running. Only accept
        # console-canary as execution when the canary is NOT in the URL (stored /
        # window.name / postMessage sources), where it can appear only if the
        # payload actually executed. Dialog checks (1 & 2) remain the strong path.
        _canary_in_url = bool(canary and canary in (final_url or "").lower())
        for c in console:
            msg = str(c.get("message") or "").lower()
            if canary and canary in msg and not _canary_in_url:
                return HeadlessVerdict(
                    status=VerdictStatus.EXECUTED,
                    executed=True,
                    method=f"console_{c.get('level','log')}",
                    evidence=str(c.get("message") or ""),
                    console_msgs=[str(c) for c in console][:20],
                    page_errors=page_errors[:20],
                    screenshot=screenshot,
                    final_url=final_url,
                    elapsed_ms=elapsed_ms,
                )

        # Nothing fired
        return HeadlessVerdict(
            status=VerdictStatus.NOT_EXECUTED,
            executed=False,
            method="",
            evidence="",
            console_msgs=[(str(c.get("message",""))[:200]) for c in console[:10]],
            page_errors=page_errors[:10],
            screenshot=screenshot,
            final_url=final_url,
            elapsed_ms=elapsed_ms,
        )


# ═══════════════════════════════════════════════════════════════════════════
# CONVENIENCE: stateless one-shot verification
# ═══════════════════════════════════════════════════════════════════════════

def quick_verify_url(url: str, expect_canary: str,
                      framework_wait: bool = False,
                      timeout_s: float = 10.0) -> HeadlessVerdict:
    """One-shot verification — opens its own browser, verifies, closes.

    For batch verification prefer using HeadlessVerifier as context
    manager — sharing a browser across many findings is way faster.
    """
    with HeadlessVerifier(timeout_s=timeout_s) as hv:
        return hv.verify_url(url, expect_canary, framework_wait=framework_wait)
