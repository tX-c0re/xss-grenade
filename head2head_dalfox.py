#!/usr/bin/env python3
"""
head2head_dalfox.py — REAL measured head-to-head: XSS Grenade vs Dalfox.

Both scanners run against the SAME local corpus (reused from
benchmark_scoreboard.py). Unlike the Burp column (which is an un-runnable
reference), BOTH columns here are MEASURED:
  - Grenade : run_scan() → evidence store + raw web-vuln hits
  - Dalfox  : the official dalfox binary, `dalfox url --url <U> -f json`,
              findings_count > 0 = detected.

Dalfox is a reflected/DOM XSS param specialist — it is given each target's
direct URL (with its parameter) so it gets a fair shot. Targets with no param
vector (static modern-class pages, stored multi-step, GraphQL, source-map, CORS)
are out of Dalfox's design scope and it will miss them — that IS the breadth
story, measured rather than claimed.

Usage: DALFOX=/path/to/dalfox.exe python head2head_dalfox.py
       (auto-discovers dalfox on PATH or /tmp/dalfox_bin if DALFOX unset)
"""
import sys, os, json, glob, subprocess, threading, time
import logging; logging.disable(logging.CRITICAL)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import socketserver
import xss_grenade as xg
import benchmark_scoreboard as B  # reuse corpus server + CORPUS + ep_of_url


def find_dalfox():
    if os.environ.get("DALFOX") and os.path.exists(os.environ["DALFOX"]):
        return os.environ["DALFOX"]
    for c in glob.glob("/tmp/dalfox_bin/**/dalfox.exe", recursive=True) + \
             glob.glob("/tmp/dalfox_bin/**/dalfox", recursive=True):
        return c
    from shutil import which
    return which("dalfox")


# Dalfox-testable URL per target (param URL where one exists; else the page).
def dalfox_url(base, key):
    params = {"refl_html": "q", "refl_attr": "name", "refl_jsctx": "q",
              "refl_title": "q", "dom_docwrite": "x", "dangling": "q",
              "svg_xml": "q", "jsonp": "callback"}
    if key in params:
        return f"{base}{key}?{params[key]}=test"
    if key in ("graphql", "sourcemap"):
        return None  # POST-only / JS bundle — outside Dalfox's URL-param model
    return f"{base}{key}"   # static page / stored / DOM — Dalfox gets its shot


def run_dalfox(dfox, url, timeout=40):
    if not url:
        return False, "n/a (no URL-param vector)"
    try:
        r = subprocess.run([dfox, "url", "--url", url, "-f", "json",
                            "--silence", "--no-color"],
                           capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        return False, f"err:{type(e).__name__}"
    out = r.stdout.strip()
    if not out:
        return False, "0 findings"
    try:
        d = json.loads(out)
        n = (d.get("meta", {}) or {}).get("findings_count",
                                          len(d.get("findings", []) or []))
        return n > 0, f"{n} finding(s)"
    except Exception:
        # dalfox sometimes prints non-JSON noise; fall back to a marker scan
        return ("Triggered XSS" in out or "[POC]" in out), "parsed-text"


def main():
    dfox = find_dalfox()
    if not dfox:
        print("Dalfox binary not found (set DALFOX=/path/to/dalfox.exe)"); return 1
    print(f"dalfox = {dfox}")

    # ── start the shared corpus server ──
    srv = socketserver.TCPServer(("127.0.0.1", 0), B.H); srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}/"
    print(f"corpus = {base}")

    # ── 1) Grenade (lean, measured via evidence store + raw hits) ──
    store = os.path.join(os.path.dirname(os.path.abspath(__file__)), "h2h_evidence.jsonl")
    try: os.remove(store)
    except OSError: pass
    raw_hits = []
    keys = ["on_hit", "on_log", "on_csp", "on_waf", "on_crawler_progress",
            "on_crawler_done", "on_progress", "on_phase", "on_finding",
            "on_status", "on_error", "on_done"]
    cb = {k: (lambda *a, **k: None) for k in keys}
    cb["on_hit"] = lambda d: raw_hits.append(d)
    print("running Grenade (lean ~2-3 min)...")
    t0 = time.time()
    xg.run_scan(
        target=base, payloads=['"><svg onload=alert(1)>', "'><svg onload=alert(1)>",
                                "<img src=x onerror=alert(1)>", "';alert(1)//"],
        workers=8, timeout=6.0, sleep_between=0.0, verify_ssl=False,
        limit_urls=None, limit_payloads=None, early_exit=False, canary=True,
        marker_enabled=True, marker_param="xss", verbose=False, report_path=None,
        json_report=None, rotate_ua=False, user_agents=[], proxies={},
        follow_redirects=True, crawl_depth=1, crawl_max_pages=40,
        enable_context_scan=True, static_js=True, dom_v6_taint=False,
        enable_sourcemap=True, enable_graphql_scan=True, proto_pollution=True,
        dom_clobbering=True, trusted_types=True, enable_postmessage_scan=True,
        enable_stored_scan=True, stored_roundtrip=True, enable_jsonp_scan=True,
        enable_dangling_scan=True, enable_svg_scan=True, cors_scan_enabled=True,
        xssi_scan_enabled=False, crlf_scan_enabled=False, headless_verify=False,
        warmup_origin=False, evidence_store_path=store, callbacks=cb)
    g_secs = time.time() - t0
    g_cov = set()
    try:
        for line in open(store, encoding="utf-8"):
            if line.strip():
                e = B.ep_of_url(json.loads(line).get("target", {}).get("url", ""))
                if e: g_cov.add(e)
    except Exception: pass
    for h in raw_hits:
        e = B.ep_of_url(h.get("url", "") + " " + str((h.get("static_js_finding") or {}).get("file", "")))
        if e: g_cov.add(e)

    # ── 2) Dalfox (measured per target) ──
    print(f"running Dalfox per target (timeout 40s each)...")
    t1 = time.time()
    d_found = {}
    for k, (cat, role, burp, desc) in B.CORPUS.items():
        if role != "vuln":
            continue
        hit, note = run_dalfox(dfox, dalfox_url(base, k))
        d_found[k] = (hit, note)
    d_secs = time.time() - t1
    srv.shutdown()

    # ── scoreboard ──
    cats = {"classic": "CLASSIC (reflected/stored/DOM)", "modern": "MODERN (2026 client-side)", "network": "NETWORK"}
    print("\n" + "=" * 80)
    print("HEAD-TO-HEAD  —  both columns MEASURED   (Grenade vs Dalfox, same corpus)")
    print("=" * 80)
    g_tot = d_tot = n_vuln = 0
    for cat in ("classic", "modern", "network"):
        print(f"\n── {cats[cat]} ──")
        for k, (c, role, burp, desc) in B.CORPUS.items():
            if c != cat or role != "vuln":
                continue
            n_vuln += 1
            g = k in g_cov; d, note = d_found.get(k, (False, "?"))
            g_tot += g; d_tot += d
            print(f"  {k:14} | Grenade {'✅' if g else '❌':2} | Dalfox {'✅' if d else '❌':2} ({note:22}) | {desc}")
    print("\n" + "=" * 80)
    print("SCORE  (measured recall on this corpus)")
    print("=" * 80)
    print(f"  XSS Grenade : {g_tot}/{n_vuln}   ({g_secs:.0f}s)")
    print(f"  Dalfox      : {d_tot}/{n_vuln}   ({d_secs:.0f}s)")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
