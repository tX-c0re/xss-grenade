#!/usr/bin/env python3
"""
profile_phases.py — where does XSS Grenade spend its time in full detection?

Runs the full (lean = no Chromium) detection config against the benchmark corpus
and times every phase, so optimization targets the biggest consumers instead of
guesses. Prints:
  1. per-phase wall-clock (from on_phase boundaries)
  2. the longest gaps between consecutive log lines (slow ops inside a phase)
"""
import sys, os, time, threading, socketserver
import logging; logging.disable(logging.CRITICAL)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import xss_grenade as xg
import benchmark_scoreboard as B


def main():
    srv = socketserver.TCPServer(("127.0.0.1", 0), B.H); srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}/"
    print(f"corpus = {base}")

    t0 = time.time()
    phases = []   # (t_rel, phase_name)
    logs = []     # (t_rel, message)
    keys = ["on_hit", "on_csp", "on_waf", "on_crawler_progress", "on_crawler_done",
            "on_progress", "on_finding", "on_status", "on_error", "on_done"]
    cb = {k: (lambda *a, **k: None) for k in keys}
    def _phase(p, d):
        tr = time.time() - t0
        phases.append((tr, str(p)))
        print(f"  [{tr:6.1f}s] → phase: {p}", file=sys.stderr, flush=True)
    cb["on_phase"] = _phase
    cb["on_log"] = lambda m, *a, **k: logs.append((time.time() - t0, str(m)[:75]))

    store = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prof_evidence.jsonl")
    try: os.remove(store)
    except OSError: pass

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
    total = time.time() - t0
    srv.shutdown()

    # ── per-phase durations (from on_phase boundaries; last phase → end) ──
    print("\n" + "=" * 66)
    print(f"PER-PHASE WALL-CLOCK   (total scan = {total:.1f}s)")
    print("=" * 66)
    durs = []
    for i, (tt, name) in enumerate(phases):
        end = phases[i + 1][0] if i + 1 < len(phases) else total
        durs.append((end - tt, name, tt))
    for d, name, tt in sorted(durs, reverse=True):
        bar = "█" * int(d / max(total, 0.1) * 40)
        print(f"  {d:6.1f}s  {name:18} {bar}")
    print(f"  {'-'*6}")
    print(f"  {sum(d for d,_,_ in durs):6.1f}s  (sum of phases)")

    # ── biggest gaps between consecutive log lines (slow ops within a phase) ──
    print("\n" + "=" * 66)
    print("TOP 12 SLOWEST STEPS  (gap between consecutive log lines)")
    print("=" * 66)
    gaps = []
    for i in range(1, len(logs)):
        gaps.append((logs[i][0] - logs[i-1][0], logs[i-1][1], logs[i][1]))
    for g, prev, cur in sorted(gaps, reverse=True)[:12]:
        print(f"  {g:6.1f}s  after: {prev[:55]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
