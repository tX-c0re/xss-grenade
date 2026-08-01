#!/usr/bin/env python3
"""
benchmark_vs_burp.py — XSS Grenade recall/precision benchmark, with a Burp
"documented-capability" reference column.

HONESTY: the Grenade column is MEASURED (a real run_scan against a local corpus,
scored from the authoritative evidence store + raw web-vuln hits). The Burp
column is a documented-capability REFERENCE (what Burp's automated scanner +
DOM Invader is known to detect for each class), NOT a live Burp run — Burp is a
licensed GUI tool that can't execute in this environment. The corpus deliberately
includes Burp's home turf (reflected / stored / DOM / prototype pollution /
postMessage) so the comparison isn't stacked.

Each target is VULNERABLE (must be found = recall) or SAFE (must not be flagged
at actionable severity = precision).
"""
import sys, os, json, html, threading, http.server, socketserver, urllib.parse
import logging; logging.disable(logging.CRITICAL)
from urllib.parse import unquote, urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import xss_grenade as xg

# ── sourcemap bundle (modern: minified → recover original → taint) ──
ORIG_VULN = ("function r(){var d=location.hash.substring(1);"
             "document.getElementById('o').innerHTML=d;}r();\n")
MIN_VULN = ("function r(){var d=location.hash.substring(1),"
            "o=document.getElementById('o');o.innerHTML=d}r()\n")
def _smap(src):
    return json.dumps({"version": 3, "file": "b.js",
                       "sources": ["webpack://app/src/render.js"], "names": [],
                       "mappings": "AAAA", "sourcesContent": [src]}).encode()

# ── static HTML pages (proven patterns) ──
PAGES = {
    "dom_hash":   "<script>document.getElementById('o').innerHTML=location.hash.slice(1);</script><div id=o></div>",
    "mutation":   "<script>var clean=DOMPurify.sanitize(input);el.innerHTML=clean;document.body.innerHTML=other;</script>",
    "proto_poll": "<script>var _=window._||{merge:function(){}};var opts={};_.merge(opts,JSON.parse(location.hash.slice(1)));document.getElementById('o2').outerHTML=opts.innerHTML;</script><div id=o2></div>",
    "dom_clob":   "<script>DOMPurify.sanitize(html,{ALLOWED_ATTR:['id','name']});var s=document.createElement('script');s.src=window.cfg.url;</script>",
    "trust_types":"<script>var u=location.hash.slice(1);document.getElementById('o').innerHTML=u;eval(u);</script><div id=o></div>",
    "postmsg":    "<script>window.addEventListener('message',function(e){document.getElementById('o').innerHTML=(e.data&&e.data.html)||e.data;});</script><div id=o></div>",
}

# corpus: key → (category, role, burp_ref, description)
#   category: classic | modern | network
#   role:     vuln | safe
#   burp_ref: strong | partial | weak  (documented automated-scanner capability)
CORPUS = {
    # ── CLASSIC — Burp's home turf (fairness) ──
    "refl_html":        ("classic", "vuln", "strong", "reflected into HTML body"),
    "refl_attr":        ("classic", "vuln", "strong", "reflected into an attribute"),
    "refl_jsctx":       ("classic", "vuln", "strong", "reflected inside <script> JS string"),
    "refl_title":       ("classic", "vuln", "strong", "reflected into <title> (PortSwigger lab)"),
    "stored_inner":     ("classic", "vuln", "strong", "STORED → innerHTML render (multi-step)"),
    "dom_hash":         ("classic", "vuln", "strong", "DOM: location.hash → innerHTML"),
    "dom_docwrite":     ("classic", "vuln", "strong", "DOM: document.write ← location.search (PortSwigger lab)"),
    "refl_escaped_safe":("classic", "safe", "strong", "HTML-escaped reflection (inert)"),
    # v10.86 CORRECTED LABEL. This was "safe (inert)" — that was factually
    # wrong, and it is exactly the hazard of a self-authored corpus: the
    # scanner agreed with our mistake, so the benchmark scored 18/18 while
    # encoding a security falsehood. Raw reflection inside an HTML comment is
    # exploitable — the payload simply closes the comment first. Proven in a
    # real browser against Google Firing Range's identical `body_comment`
    # template: `--><svg onload=alert(1)>` executed. See bench_firingrange/.
    "refl_comment":     ("classic", "vuln", "strong", "reflection inside <!-- --> (breaks out via -->)"),
    "refl_comment_esc": ("classic", "safe", "strong", "comment reflection with --> neutralised (inert)"),
    "refl_js_safe":     ("classic", "safe", "strong", "JS string properly escaped (inert)"),
    # ── MODERN — Grenade's edge ──
    "mutation":         ("modern", "vuln", "partial", "mutation XSS (sanitizer bypass)"),
    "proto_poll":       ("modern", "vuln", "strong",  "prototype pollution → gadget"),
    "dom_clob":         ("modern", "vuln", "partial", "DOM clobbering → script.src"),
    "trust_types":      ("modern", "vuln", "weak",    "Trusted Types / DOM sink + eval"),
    "postmsg":          ("modern", "vuln", "strong",  "postMessage → innerHTML"),
    "graphql":          ("modern", "vuln", "partial", "GraphQL reflected XSS"),
    "sourcemap":        ("modern", "vuln", "weak",    "source-map de-minify → taint"),
    "mutation_safe":    ("modern", "safe", "n/a",     "innerHTML=DOMPurify.sanitize() (inert)"),
    # ── NETWORK ──
    "cors_cred":        ("network", "vuln", "strong",  "CORS ACAO-reflect + credentials"),
    "jsonp":            ("network", "vuln", "partial", "JSONP callback injection"),
    "dangling":         ("network", "vuln", "partial", "dangling markup (scriptless)"),
    "svg_xml":          ("network", "vuln", "partial", "SVG/XML reflection"),
    "cors_nocred":      ("network", "safe", "strong",  "CORS without credentials (inert)"),
}

_STORE = []  # stored comments for the stored_inner target


def _home_links():
    out = []
    for k in ("dom_hash", "mutation", "proto_poll", "dom_clob", "trust_types",
              "postmsg", "mutation_safe"):
        q = "?v=1" if CORPUS[k][1] == "vuln" else ""
        out.append(f'<a href="/{k}{q}">{k}</a>')
    for k, qp in (("refl_html", "q"), ("refl_attr", "name"), ("refl_jsctx", "q"),
                  ("refl_title", "q"), ("dom_docwrite", "x"), ("refl_js_safe", "q"),
                  ("refl_escaped_safe", "q"), ("refl_comment", "q"),
                  ("refl_comment_esc", "q"),
                  ("cors_cred", None), ("cors_nocred", None),
                  ("jsonp", "callback"), ("dangling", "q"), ("svg_xml", "q")):
        href = f"/{k}?{qp}=test" if qp else f"/{k}"
        out.append(f'<a href="{href}">{k}</a>')
    out.append('<a href="/stored_inner">stored_inner</a>')
    return ("<html><body><h1>bench</h1>" + "".join(out)
            + '<script src="/sourcemap.js"></script></body></html>')


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _s(self, body, ct="text/html", extra=None, code=200):
        if isinstance(body, str): body = body.encode()
        self.send_response(code); self.send_header("Content-Type", ct)
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def do_HEAD(self):
        self.send_response(200); self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", "0"); self.end_headers()
    def _q(self): return parse_qs(urlparse(self.path).query)
    def do_GET(self):
        p = urlparse(self.path).path; name = p.lstrip("/"); q = self._q()
        org = self.headers.get("Origin", "")
        if p in ("/", "/index.html"):
            self._s(_home_links())
        elif name in PAGES:
            self._s(f"<html><body>{PAGES[name]}</body></html>")
        elif name == "refl_html":
            self._s(f"<html><body>Hi {q.get('q',[''])[0]}</body></html>")
        elif name == "refl_attr":
            self._s(f"<html><body><input value='{q.get('name',[''])[0]}'></body></html>")
        elif name == "refl_jsctx":
            self._s(f"<html><body><script>var x='{q.get('q',[''])[0]}';</script></body></html>")
        elif name == "refl_title":
            self._s(f"<html><head><title>{q.get('q',[''])[0]}</title></head><body>t</body></html>")
        elif name == "dom_docwrite":
            # DOM XSS: document.write of a value read from location.search
            self._s("<html><body><script>document.write("
                    "new URLSearchParams(location.search).get('x')||'');</script></body></html>")
        elif name == "refl_js_safe":
            # JS string with ' \\ and </ properly escaped → inert (FP trap)
            v = q.get('q',[''])[0].replace("\\","\\\\").replace("'","\\'").replace("</","<\\/")
            self._s(f"<html><body><script>var x='{v}';</script></body></html>")
        elif name == "refl_escaped_safe":
            self._s(f"<html><body>Hi {html.escape(q.get('q',[''])[0])}</body></html>")
        elif name == "refl_comment":
            # VULNERABLE: the payload can close the comment with --> and then
            # write live markup. (Was mislabelled "safe" before v10.86.)
            self._s(f"<html><body><!-- {q.get('q',[''])[0]} --></body></html>")
        elif name == "refl_comment_esc":
            # The genuine safe control: neutralise the comment terminator so
            # the reflection really is inert.
            v = q.get('q', [''])[0].replace("--!>", "").replace("-->", "").replace("<", "&lt;")
            self._s(f"<html><body><!-- {v} --></body></html>")
        elif name == "stored_inner":
            # level-2 style: stored posts rendered client-side via innerHTML
            items = "".join("<div>" + c + "</div>" for c in _STORE)
            self._s("<html><body><form method=POST action='/stored_inner'>"
                    "<input name=msg><button>post</button></form>"
                    f"<div id=board>{items}</div></body></html>")
        elif name == "cors_cred":
            self._s('{"secret":1}', "application/json",
                    {"Access-Control-Allow-Origin": org or "*",
                     "Access-Control-Allow-Credentials": "true"})
        elif name == "cors_nocred":
            self._s('{"ok":1}', "application/json",
                    {"Access-Control-Allow-Origin": org or "*"})
        elif name == "jsonp":
            cb = q.get("callback", ["cb"])[0]
            self._s(f'{cb}({{"status":"ok"}});', "application/javascript")
        elif name == "dangling":
            self._s(f'<img src="/a.png" alt="{q.get("q",[""])[0]}"><p>x</p>')
        elif name == "svg_xml":
            self._s(f'<svg xmlns="http://www.w3.org/2000/svg">{q.get("q",[""])[0]}</svg>', "image/svg+xml")
        elif name == "sourcemap.js":
            self._s(MIN_VULN + "//# sourceMappingURL=/sourcemap.js.map\n", "application/javascript")
        elif name == "sourcemap.js.map":
            self._s(_smap(ORIG_VULN), "application/json")
        else:
            self._s("<html>ok</html>")
    def do_POST(self):
        p = urlparse(self.path).path
        if p == "/stored_inner":
            n = int(self.headers.get("Content-Length", 0) or 0)
            msg = urllib.parse.parse_qs(self.rfile.read(n).decode() if n else "").get("msg", [""])[0]
            _STORE.append(msg)
            self.send_response(302); self.send_header("Location", "/stored_inner"); self.end_headers()
            return
        if p != "/graphql":
            self._s('{"errors":[{"message":"nf"}]}', "application/json", code=404); return
        n = int(self.headers.get("Content-Length", 0) or 0)
        try: req = json.loads(self.rfile.read(n).decode() or "{}") if n else {}
        except Exception: req = {}
        query = req.get("query", "") or ""; variables = req.get("variables", {}) or {}
        if "__typename" in query and "<" not in query and not variables:
            self._s('{"data":{"__typename":"Query"}}', "application/json"); return
        if "<" in query:
            self._s(json.dumps({"errors": [{"message": f'Cannot query field "{query}" on type "Query".'}]}), "application/json"); return
        if "q" in variables:
            self._s(json.dumps({"errors": [{"message": f'Variable "$q" got invalid value {variables["q"]}.'}]}), "application/json"); return
        self._s('{"data":{"__typename":"Query"}}', "application/json")


def ep_of_url(u):
    u = unquote(u or "")
    if "render.js" in u or "sourcemap" in u: return "sourcemap"
    if "/graphql" in u: return "graphql"
    for k in CORPUS:
        if "/" + k in u: return k
    return None


def run():
    srv = socketserver.TCPServer(("127.0.0.1", 0), H); srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{srv.server_address[1]}/"
    # link /graphql so discovery finds it
    print(f"target = {target}")

    store = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bench_evidence.jsonl")
    try: os.remove(store)
    except OSError: pass
    payloads = ['"><svg onload=alert(1)>', "'><svg onload=alert(1)>",
                "<img src=x onerror=alert(1)>", '"><script>alert(1)</script>',
                "</textarea><svg onload=alert(1)>", "--><svg onload=alert(1)>",
                "';alert(1)//", "</script><svg onload=alert(1)>"]
    raw_hits, logs = [], []
    _keys = ["on_hit", "on_log", "on_csp", "on_waf", "on_crawler_progress",
             "on_crawler_done", "on_progress", "on_phase", "on_finding",
             "on_status", "on_error", "on_done"]
    cb = {k: (lambda *a, **k: None) for k in _keys}
    cb["on_hit"] = lambda d: raw_hits.append(d)

    # --deep: add Chromium phases (DOM v6 runtime + headless confirmation) for a
    # trustworthy-but-slow (~15 min) run. Default (lean) skips Chromium and
    # measures recall from static/HTTP detection + the evidence store (~2-3 min),
    # which is what you run after each etapa to track progress vs Burp.
    deep = "--deep" in sys.argv
    print(f"mode = {'DEEP (headless+dom-v6)' if deep else 'LEAN (no Chromium, ~2-3 min)'}")
    xg.run_scan(
        target=target, payloads=payloads, workers=8, timeout=6.0, sleep_between=0.0,
        verify_ssl=False, limit_urls=None, limit_payloads=None, early_exit=False,
        canary=True, marker_enabled=True, marker_param="xss", verbose=False,
        report_path=None, json_report=None, rotate_ua=False, user_agents=[],
        proxies={}, follow_redirects=True, crawl_depth=1, crawl_max_pages=40,
        enable_context_scan=True, static_js=True, dom_v6_taint=deep,
        enable_sourcemap=True, enable_graphql_scan=True, proto_pollution=True,
        dom_clobbering=True, trusted_types=True, enable_postmessage_scan=True,
        enable_stored_scan=True, stored_roundtrip=True,
        enable_jsonp_scan=True, enable_dangling_scan=True, enable_svg_scan=True,
        cors_scan_enabled=True, xssi_scan_enabled=False, crlf_scan_enabled=False,
        headless_verify=deep, warmup_origin=False,
        evidence_store_path=store, callbacks=cb)
    srv.shutdown()

    SEV = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    ev = []
    try:
        for line in open(store, encoding="utf-8"):
            if line.strip(): ev.append(json.loads(line))
    except Exception: pass

    covered, hardfp = set(), {}
    for r in ev:
        e = ep_of_url(r.get("target", {}).get("url", ""))
        if e: covered.add(e)
        v = r.get("verdict", {})
        if CORPUS.get(e, (None, None))[1] == "safe" and SEV.get(str(v.get("severity")), 0) >= 3 and v.get("fp_risk") is not True:
            hardfp[e] = v.get("severity")
    for h in raw_hits:
        e = ep_of_url(h.get("url", "") + " " + str((h.get("static_js_finding") or {}).get("file", "")))
        if e: covered.add(e)
        src = (h.get("source") or "").lower()
        if (CORPUS.get(e, (None, None))[1] == "safe" and any(n in src for n in ("cors", "xssi"))
                and SEV.get((h.get("severity") or "").lower(), 0) >= 3 and h.get("fp_risk") is not True):
            hardfp[e] = h.get("severity")

    BURP = {"strong": "✅ strong", "partial": "🟡 partial", "weak": "❌ weak", "n/a": "—"}
    cats = {"classic": "CLASSIC (Burp home turf)", "modern": "MODERN (2026 client-side)", "network": "NETWORK"}
    print("\n" + "=" * 78)
    print("SCOREBOARD  —  Grenade = MEASURED   |   Burp = documented capability (ref)")
    print("=" * 78)
    vuln_keys = [k for k, m in CORPUS.items() if m[1] == "vuln"]
    g_found, g_modern_found, modern_vuln = 0, 0, 0
    for cat in ("classic", "modern", "network"):
        print(f"\n── {cats[cat]} ──")
        for k, (c, role, burp, desc) in CORPUS.items():
            if c != cat: continue
            if role == "vuln":
                hit = k in covered
                g_found += hit
                if cat == "modern": modern_vuln += 1; g_modern_found += hit
                print(f"  {'FOUND ✓' if hit else 'MISS  ✗':9} {k:18} | Grenade {'✅' if hit else '❌':2} | Burp {BURP[burp]:11} | {desc}")
            else:
                isfp = k in hardfp
                print(f"  {'FP ✗' if isfp else 'safe ✓':9} {k:18} | Grenade {'❌FP' if isfp else '✅ok':4} | Burp {BURP[burp]:11} | {desc}")

    print("\n" + "=" * 78)
    print("TOTALS")
    print("=" * 78)
    print(f"  Grenade RECALL    : {g_found}/{len(vuln_keys)} vulnerable targets found  (MEASURED)")
    print(f"  Grenade HARD FP   : {len(hardfp)} safe targets flagged high/crit w/o fp_risk → {sorted(hardfp) or 'NONE ✓'}")
    print(f"  MODERN-class recall: {g_modern_found}/{modern_vuln}  (the classes Burp's automated scanner is weakest on)")
    burp_modern_strong = sum(1 for k, m in CORPUS.items() if m[0] == "modern" and m[1] == "vuln" and m[2] == "strong")
    print(f"  Burp MODERN (ref) : ~{burp_modern_strong}/{modern_vuln} reliably automated (rest partial/weak — DOM Invader is interactive)")
    missed = sorted(k for k in vuln_keys if k not in covered)
    if missed:
        print(f"  MISSED            : {missed}")
    print("=" * 78)

    # ── regression thresholds: recall must hold, zero actionable FP ──
    # LEAN mode (no Chromium) can't confirm some headless-only classes; allow a
    # small miss budget there. DEEP mode must hit full recall.
    recall_floor = len(vuln_keys) if deep else max(0, len(vuln_keys) - 3)
    ok_recall = g_found >= recall_floor
    ok_fp = len(hardfp) == 0
    print(f"  THRESHOLDS: recall {g_found} >= {recall_floor}? {'✓' if ok_recall else '✗'}"
          f"   |   hard-FP == 0? {'✓' if ok_fp else '✗'}")
    if ok_recall and ok_fp:
        print("  RESULT: PASS ✓  — track this row across etapy to watch the gap to Burp")
        return 0
    print("  RESULT: FAIL ✗  — a change moved the scoreboard the WRONG way")
    return 1


if __name__ == "__main__":
    sys.exit(run())
