"""
_dom_v6.py
==========
Taint-aware DOM XSS detection.

Background
----------
Existing DOMValidator (v5) hooks sinks (innerHTML, eval, document.write) and
checks if marker landed there. Limitation: doesn't track WHERE the tainted
data came from, doesn't catch source→sink chains where the source isn't
the URL parameter we're testing (e.g., location.hash, document.cookie,
window.name, postMessage).

The classic example that v5 missed: sudo.co.il level19. A signed `tr`
parameter is parsed by JS, decoded, and written to DOM. v5's "inject canary
into q, watch for sink" can't see the chain because the relevant data flow
is `location.search → URLSearchParams.get('tr') → atob/uudecode → innerHTML`.

What v6 adds
------------
1. Source tracking — hook getters on:
   - location.{href, search, hash, pathname}
   - document.{URL, documentURI, referrer, cookie}
   - window.name
   - localStorage/sessionStorage.getItem
   - URLSearchParams.get
   - postMessage event.data
2. Source→sink chain reconstruction
   When sink fires with a marker, look back through source_reads for matching
   marker → emit "source X feeds sink Y" finding.
3. Per-parameter canary injection
   For each (url, query_param), inject UNIQUE canary, run page, see which
   sink received which canary.
4. Auto-interaction
   After page load + grace, fire click/hover/focus/submit/change on visible
   elements + dispatch hashchange. Catches XSS that requires user action.
5. Hash/fragment poisoning
   Inject `#javascript:alert(<canary>)` in fragment + canary in `name=`,
   covers Twitter-style `location.hash.split("#!")` patterns.

Public API
----------

    DOMV6Verifier(...) — context manager, persistent browser
        .scan_url(url, params=None, headers=None) → ScanResult
            For URL with N query params, runs N+ tests with unique canaries
            and aggregates source/sink findings.

    ScanResult.findings → List[DOMFinding]
        Each finding is a confirmed source→sink chain or executed dialog.
"""

from __future__ import annotations

import json
import os
import time
import logging
import random
import string
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlunparse, urlencode

log = logging.getLogger("xss_grenade.dom_v6")

# Optional Playwright
try:
    from playwright.sync_api import sync_playwright
    from playwright.sync_api import TimeoutError as PWTimeoutError
    _PW_AVAILABLE = True
except ImportError:
    _PW_AVAILABLE = False
    sync_playwright = None
    PWTimeoutError = Exception


# ──────────────────────────────────────────────────────────────────────────────
# DATA TYPES
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class SourceRead:
    source: str
    value: str
    has_marker: bool
    ts: int


@dataclass
class SinkHit:
    sink: str
    value: str
    marker_matches: List[str]
    stack: str = ""
    ts: int = 0


@dataclass
class TaintChain:
    """A confirmed source → sink data flow."""
    source: str
    sink: str
    marker: str          # canary identifying which injection point fed the chain
    chain_value: str
    delta_ms: int = 0


@dataclass
class DOMFinding:
    url: str                  # tested URL with canary
    target_param: str         # which param was injected with this canary
    canary: str
    triggered: bool = False
    triggered_by: str = ""    # canary that won (might be different from target_param)
    sink_hits: List[SinkHit] = field(default_factory=list)
    source_reads: List[SourceRead] = field(default_factory=list)
    taint_chains: List[TaintChain] = field(default_factory=list)
    dialogs: List[Dict] = field(default_factory=list)
    csp_violations: List[Dict] = field(default_factory=list)
    page_errors: List[Dict] = field(default_factory=list)
    tt_policies: List[Dict] = field(default_factory=list)  # runtime Trusted Types policy probes
    tt_enforced: Optional[bool] = None  # was require-trusted-types-for 'script' actually enforced on this load? (tri-state)
    interactions_done: int = 0
    elapsed_ms: int = 0
    error: str = ""

    @property
    def confirmed(self) -> bool:
        """A finding shows a TAINT FLOW if a dialog fired with our marker, or a
        sink received our marker. NOTE: for an HTML-parse sink a bare marker is
        only a flow (not proof of exploit) — use `exploit_confirmed` for the
        promote-to-high / dom_verified decision."""
        return (
            self.triggered or
            any(d.get("marker_matches") for d in self.dialogs) or
            any(s.marker_matches for s in self.sink_hits)
        )

    @property
    def exploit_confirmed(self) -> bool:
        """STRONG evidence of ACTUAL execution (not merely a taint flow): a
        dialog/page-error carrying our marker, OR the marker reaching a code-
        exec / scheme-gated sink. v10.79 FP fix: a bare alphanumeric canary
        merely appearing in an HTML-parse sink (innerHTML/document.write/
        insertAdjacentHTML/srcdoc/DOMParser/…) is NOT proof — HTML-escaping
        leaves the token byte-identical, so an escaped-SAFE reflection would
        otherwise be reported as a browser-CONFIRMED XSS."""
        if any(d.get("marker_matches") for d in self.dialogs):
            return True
        if any(pe.get("marker_matches") for pe in self.page_errors):
            return True
        return any(s.marker_matches and is_exploit_sink(s.sink)
                   for s in self.sink_hits)

    @property
    def has_source_sink_chain(self) -> bool:
        """At least one taint chain reached a sink with our marker."""
        return any(
            tc.marker == self.canary or self.canary in (tc.chain_value or "")
            for tc in self.taint_chains
        )


@dataclass
class ScanResult:
    target_url: str
    findings: List[DOMFinding] = field(default_factory=list)

    @property
    def confirmed(self) -> List[DOMFinding]:
        return [f for f in self.findings if f.confirmed]

    @property
    def total_sinks(self) -> int:
        return sum(len(f.sink_hits) for f in self.findings)

    @property
    def total_sources(self) -> int:
        return sum(len(f.source_reads) for f in self.findings)

    @property
    def tt_enforced(self) -> Optional[bool]:
        """Page-level Trusted Types enforcement, folded across all loads of this
        page. True if ANY load observed require-trusted-types-for 'script' active;
        False if every load explicitly reported it inactive; None if unknown
        (e.g. older hook that did not probe)."""
        vals = [f.tt_enforced for f in self.findings if f.tt_enforced is not None]
        if not vals:
            return None
        return True if any(v is True for v in vals) else False


# ──────────────────────────────────────────────────────────────────────────────
# CANARY GENERATION
# ──────────────────────────────────────────────────────────────────────────────

# Sinks where a bare (breakout-free) canary reaching them IS genuine proof of
# exploitability: the value is executed as CODE.
_DOM_V6_CODE_SINKS = frozenset({
    "eval", "Function", "setTimeout(string)", "setInterval(string)",
})


def is_exploit_sink(sink_name: str) -> bool:
    """True iff a bare marker reaching `sink_name` proves exploitability — the
    value is executed as CODE, or the sink hook already gated on a dangerous
    scheme (javascript:/data:). HTML-parse sinks (innerHTML/document.write/
    insertAdjacentHTML/iframe.srcdoc/DOMParser/Range.createContextualFragment/
    parseHTMLUnsafe/shadowRoot.innerHTML/serviceWorker.register) return False:
    a bare alphanumeric canary there is only a taint flow, since HTML-escaping
    leaves it byte-identical and cannot distinguish safe from exploitable."""
    if not sink_name:
        return False
    if sink_name in _DOM_V6_CODE_SINKS:
        return True
    return ("scheme" in sink_name) or ("javascript:" in sink_name)


def make_canary(prefix: str = "XSGD") -> str:
    """Generate unique canary token (DOM v6 prefix XSGD)."""
    rnd = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
    return f"{prefix}_{rnd}"


# ──────────────────────────────────────────────────────────────────────────────
# HOOK SCRIPT LOADING
# ──────────────────────────────────────────────────────────────────────────────

def _load_hooks_script(markers: List[str]) -> str:
    """Load dom_hooks_v6.js + substitute placeholders."""
    here = os.path.dirname(os.path.abspath(__file__))
    hooks_path = os.path.join(here, "dom_hooks_v6.js")
    try:
        with open(hooks_path, "r", encoding="utf-8") as f:
            template = f.read()
    except IOError:
        # Inline fallback — minimal hooks for when file is missing
        return _inline_fallback_hooks(markers)
    return template.replace(
        "__XSS_MARKERS_PLACEHOLDER__",
        json.dumps(markers)
    )


def _inline_fallback_hooks(markers: List[str]) -> str:
    """Minimal inline hooks if dom_hooks_v6.js is missing."""
    return """
    (function(){
        window.__xssg_state__ = {
            markers: %s,
            sink_hits: [], source_reads: [], taint_chains: [],
            dialogs: [], page_errors: [], csp_violations: [],
            triggered: false, triggered_by: null, interactions_done: 0
        };
        var S = window.__xssg_state__;
        function findM(s){var r=[];try{var x=String(s);for(var i=0;i<S.markers.length;i++)if(x.indexOf(S.markers[i])!==-1)r.push(S.markers[i]);}catch(e){}return r;}
        function rec(n,v){var m=findM(v);S.sink_hits.push({sink:n,value:String(v).substring(0,300),marker_matches:m,ts:Date.now()});if(m.length){S.triggered=true;if(!S.triggered_by)S.triggered_by=m[0];}}
        try{var d=Object.getOwnPropertyDescriptor(Element.prototype,'innerHTML');var s=d.set;Object.defineProperty(Element.prototype,'innerHTML',{set:function(v){rec('innerHTML',v);return s.call(this,v);},get:d.get,configurable:true});}catch(e){}
        try{var oe=window.eval;window.eval=function(c){rec('eval',c);return oe.call(this,c);};}catch(e){}
        ['alert','confirm','prompt'].forEach(function(fn){try{var o=window[fn];window[fn]=function(m){S.dialogs.push({fn:fn,message:String(m||''),marker_matches:findM(m),ts:Date.now()});if(findM(m).length){S.triggered=true;if(!S.triggered_by)S.triggered_by=findM(m)[0];}return undefined;};}catch(e){}});
        window.__xssg_auto_interact__ = function(){return 0;};
    })();
    """ % json.dumps(markers)


# ──────────────────────────────────────────────────────────────────────────────
# URL MUTATION
# ──────────────────────────────────────────────────────────────────────────────

def inject_canary_into_param(url: str, param: str, canary: str) -> str:
    """Replace param's value in URL with canary, preserving other params."""
    parsed = urlparse(url)
    q = parse_qsl(parsed.query, keep_blank_values=True)
    new_q = [(k, canary if k == param else v) for k, v in q]
    if not any(k == param for k, _ in q):
        new_q.append((param, canary))
    return urlunparse(parsed._replace(query=urlencode(new_q, doseq=True)))


def inject_canary_into_fragment(url: str, canary: str) -> str:
    """Append canary to fragment, supporting both #canary and #!canary patterns.

    For SPA hash-mode URLs like `http://x/#/search?q=test`, the fragment
    `/search?q=test` IS the route + its params. Replacing the fragment with
    `!canary` breaks the route. Instead, inject canary into the fragment's
    query string (or append `?canary=val` if no query).
    """
    parsed = urlparse(url)
    frag = parsed.fragment or ""
    # SPA hash-mode pattern: fragment starts with / (e.g. /search?q=test)
    if frag.startswith("/"):
        if "?" in frag:
            # Already has query in fragment — inject canary as additional param
            new_frag = f"{frag}&__xsgd_canary={canary}"
        else:
            new_frag = f"{frag}?__xsgd_canary={canary}"
        # Also inject directly into existing query keys (replace value with canary)
        # This is what SPA Angular/React routes actually read.
        if "?" in frag:
            base, qs = frag.split("?", 1)
            from urllib.parse import parse_qsl, urlencode
            q_pairs = parse_qsl(qs, keep_blank_values=True)
            if q_pairs:
                # Replace first param's value with canary (most likely sink target)
                first_key = q_pairs[0][0]
                new_pairs = [(first_key, canary)] + q_pairs[1:]
                new_frag = f"{base}?{urlencode(new_pairs)}"
        return urlunparse(parsed._replace(fragment=new_frag))
    # Non-SPA fragment (legacy hash routers / Twitter-style #!path)
    return urlunparse(parsed._replace(fragment=f"!{canary}"))


def list_query_params(url: str) -> List[str]:
    parsed = urlparse(url)
    return [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]


# ──────────────────────────────────────────────────────────────────────────────
# VERIFIER — context manager
# ──────────────────────────────────────────────────────────────────────────────

class DOMV6Verifier:
    """Persistent browser pool for DOM XSS taint analysis.

    Use as context manager:
        with DOMV6Verifier() as v:
            result = v.scan_url("http://target/page?q=test&tr=sig")
            for f in result.confirmed:
                print(f"{f.target_param}: {f.taint_chains}")
    """

    def __init__(self,
                 headless: bool = True,
                 timeout_s: float = 8.0,
                 grace_ms: int = 1500,
                 auto_interact: bool = True,
                 ignore_https_errors: bool = True,
                 user_agent: Optional[str] = None,
                 max_params: int = 12):
        self.headless = headless
        self.timeout_s = timeout_s
        self.grace_ms = grace_ms
        self.auto_interact = auto_interact
        self.ignore_https_errors = ignore_https_errors
        self.user_agent = user_agent or (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
        )
        self.max_params = int(max_params)

        self._pw = None
        self._browser = None
        self._available = _PW_AVAILABLE

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
                ],
            )
        except Exception as e:
            log.warning("Playwright launch failed: %s", e)
            self._available = False
            self._browser = None
        return self

    def __exit__(self, *args):
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

    # ──────────────────────────────────────────────────────────────────────
    # PUBLIC SCAN API
    # ──────────────────────────────────────────────────────────────────────

    def scan_url(self,
                  url: str,
                  params: Optional[List[str]] = None,
                  headers: Optional[Dict[str, str]] = None,
                  cookies: Optional[List[Dict]] = None) -> ScanResult:
        """Run DOM taint analysis on url, injecting unique canary into each
        query param + fragment.

        Returns ScanResult with one DOMFinding per probe.
        """
        result = ScanResult(target_url=url)
        if not self._available:
            return result

        # Determine which params to test
        if params is None:
            params = list_query_params(url)
        # Cap to prevent runaway
        params = params[:self.max_params]

        # Build probe list: one per param + one for fragment
        probes: List[Tuple[str, str, str]] = []   # (target_param, canary, test_url)
        for p in params:
            cy = make_canary()
            test_url = inject_canary_into_param(url, p, cy)
            probes.append((p, cy, test_url))

        # Always probe fragment (even when no query params)
        frag_canary = make_canary()
        probes.append(("__fragment__", frag_canary,
                        inject_canary_into_fragment(url, frag_canary)))

        # Multi-canary mode: inject ALL canaries in one page load via headers/JS?
        # Not safe — server may sanitize differently per param. Run sequentially
        # but reuse browser for speed.

        for target_param, canary, test_url in probes:
            f = self._scan_single(test_url, target_param, canary,
                                   headers=headers, cookies=cookies)
            result.findings.append(f)
        return result

    def scan_url_multi_canary(self,
                                url: str,
                                params: Optional[List[str]] = None,
                                headers: Optional[Dict[str, str]] = None,
                                cookies: Optional[List[Dict]] = None) -> ScanResult:
        """Faster mode: ALL params get unique canaries in ONE request.

        Tradeoff: if server sanitizes only specific params, multi-canary may
        produce ambiguous taint chains. But 5x faster than sequential.
        """
        result = ScanResult(target_url=url)
        if not self._available:
            return result

        if params is None:
            params = list_query_params(url)
        params = params[:self.max_params]

        # Build URL with all canaries
        canaries: Dict[str, str] = {p: make_canary() for p in params}
        frag_canary = make_canary()

        cur_url = url
        for p, cy in canaries.items():
            cur_url = inject_canary_into_param(cur_url, p, cy)
        cur_url = inject_canary_into_fragment(cur_url, frag_canary)

        all_canaries = list(canaries.values()) + [frag_canary]
        f = self._scan_single(cur_url, "__multi__", all_canaries[0],
                                headers=headers, cookies=cookies,
                                extra_canaries=all_canaries[1:])

        # Map sink_hits + taint_chains back to which canary won
        # (already in marker_matches field of each)
        f.target_param = "__multi__"
        result.findings.append(f)

        # Re-emit canary→param mapping so consumer knows which param caused
        # which marker_match
        f._canary_to_param = {cy: p for p, cy in canaries.items()}
        f._canary_to_param[frag_canary] = "__fragment__"
        return result

    # ──────────────────────────────────────────────────────────────────────
    # CORE PROBE
    # ──────────────────────────────────────────────────────────────────────

    def _scan_single(self,
                       test_url: str,
                       target_param: str,
                       canary: str,
                       headers: Optional[Dict[str, str]] = None,
                       cookies: Optional[List[Dict]] = None,
                       extra_canaries: Optional[List[str]] = None) -> DOMFinding:
        """Single page load with canary(ies); collect state."""
        f = DOMFinding(url=test_url, target_param=target_param, canary=canary)

        if not self._available or self._browser is None:
            f.error = "playwright_unavailable"
            return f

        all_markers = [canary] + (extra_canaries or [])
        start = time.perf_counter()

        ctx = None
        page = None
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

            # Inject hooks BEFORE any page script runs
            page.add_init_script(_load_hooks_script(all_markers))

            # Auto-dismiss native dialogs that slip past hook
            page.on("dialog", lambda d: (
                f.dialogs.append({
                    "fn": d.type, "message": d.message,
                    "marker_matches": [m for m in all_markers if m in (d.message or "")],
                    "ts": int(time.time() * 1000),
                    "native": True
                }),
                d.dismiss()
            ))

            # Listen for pageerror
            def on_pageerr(err):
                try:
                    f.page_errors.append({
                        "message": str(err)[:300],
                        "ts": int(time.time() * 1000)
                    })
                except Exception:
                    pass
            page.on("pageerror", on_pageerr)

            # Navigate
            try:
                page.goto(test_url, wait_until="domcontentloaded",
                          timeout=self.timeout_s * 1000)
            except PWTimeoutError:
                pass
            except Exception as e:
                f.error = f"nav_failed: {type(e).__name__}: {e}"
                # Still try to read state
            # Wait for SPA bootstrap
            try:
                page.wait_for_timeout(self.grace_ms)
            except Exception:
                pass

            # Auto-interaction (click/focus/etc.) - some XSS only fires on interaction
            if self.auto_interact:
                try:
                    n = page.evaluate("() => (window.__xssg_auto_interact__ ? window.__xssg_auto_interact__() : 0)")
                    f.interactions_done = int(n or 0)
                    # Grace after interaction
                    page.wait_for_timeout(500)
                except Exception:
                    pass

            # Pull state
            try:
                state = page.evaluate("() => window.__xssg_state__ || null")
            except Exception:
                state = None

            if state:
                # Sink hits
                for sh in (state.get("sink_hits") or []):
                    try:
                        f.sink_hits.append(SinkHit(
                            sink=str(sh.get("sink", "")),
                            value=str(sh.get("value", ""))[:300],
                            marker_matches=list(sh.get("marker_matches") or []),
                            stack=str(sh.get("stack") or "")[:300],
                            ts=int(sh.get("ts") or 0),
                        ))
                    except Exception:
                        continue
                # Source reads
                for sr in (state.get("source_reads") or []):
                    try:
                        f.source_reads.append(SourceRead(
                            source=str(sr.get("source", "")),
                            value=str(sr.get("value", ""))[:300],
                            has_marker=bool(sr.get("has_marker", False)),
                            ts=int(sr.get("ts") or 0),
                        ))
                    except Exception:
                        continue
                # Taint chains
                for tc in (state.get("taint_chains") or []):
                    try:
                        f.taint_chains.append(TaintChain(
                            source=str(tc.get("source", "")),
                            sink=str(tc.get("sink", "")),
                            marker=str(tc.get("marker", "")),
                            chain_value=str(tc.get("chain_value", ""))[:300],
                            delta_ms=int(tc.get("delta_ms") or 0),
                        ))
                    except Exception:
                        continue
                # Dialogs from hook
                for d in (state.get("dialogs") or []):
                    try:
                        f.dialogs.append({
                            "fn": str(d.get("fn", "")),
                            "message": str(d.get("message", ""))[:300],
                            "marker_matches": list(d.get("marker_matches") or []),
                            "ts": int(d.get("ts") or 0),
                        })
                    except Exception:
                        continue
                # CSP violations
                for cv in (state.get("csp_violations") or []):
                    try:
                        f.csp_violations.append(dict(cv))
                    except Exception:
                        continue
                # Page errors from hook
                for pe in (state.get("page_errors") or []):
                    try:
                        f.page_errors.append(dict(pe))
                    except Exception:
                        continue
                # Runtime Trusted Types policy probes
                for tp in (state.get("tt_policies") or []):
                    try:
                        f.tt_policies.append(dict(tp))
                    except Exception:
                        continue
                # Trusted Types enforcement signal (tri-state). Kept separate so
                # the runtime policy audit can tell an ACTIVE 'default' backdoor
                # from an inert pass-through policy on a page that never enforces
                # require-trusted-types-for 'script'.
                _tt_enf = state.get("tt_enforced", None)
                if _tt_enf is True or _tt_enf is False:
                    f.tt_enforced = _tt_enf

                f.triggered = bool(state.get("triggered", False))
                f.triggered_by = str(state.get("triggered_by") or "")

        except Exception as e:
            f.error = f"{type(e).__name__}: {e}"
        finally:
            try:
                if page: page.close()
            except Exception: pass
            try:
                if ctx: ctx.close()
            except Exception: pass

        f.elapsed_ms = int((time.perf_counter() - start) * 1000)
        return f


# ──────────────────────────────────────────────────────────────────────────────
# CONVENIENCE: One-shot scan
# ──────────────────────────────────────────────────────────────────────────────

def quick_scan_url(url: str,
                    params: Optional[List[str]] = None,
                    timeout_s: float = 8.0) -> ScanResult:
    """One-shot scan — opens own browser, scans, closes.

    For batch, use DOMV6Verifier as context manager.
    """
    with DOMV6Verifier(timeout_s=timeout_s) as v:
        return v.scan_url(url, params=params)
