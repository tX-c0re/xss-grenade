#!/usr/bin/env python3
"""
benchmark_firingrange.py — measure XSS Grenade against an INDEPENDENT corpus.

  corpus      : Google Firing Range page templates, used verbatim (fr_server.py)
  ground truth: measured empirically in real Chromium (fr_oracle.py) — an
                endpoint counts as vulnerable only if a browser actually
                executed a public XSS payload on it
  measurement : this file. Runs run_scan() against the corpus and compares the
                findings to the oracle labels.

Nothing in the corpus or the labels was authored or tuned by this project,
which is the entire point: benchmark_scoreboard.py (the in-repo corpus) scores
18/18 with 0 FP, but it was written by us, so it can only demonstrate
self-consistency.

Scoring is reported under two conventions so the number cannot be cherry-picked:

  LENIENT  recall  = endpoint produced ANY finding
           FP      = safe endpoint reported at >= high without fp_risk
           (the convention benchmark_scoreboard.py already uses: an `info`
            note is not "crying wolf")

  STRICT   both sides thresholded at >= high without fp_risk
           (what a user actually sees as "this is a vulnerability")

Usage:
    python benchmark_firingrange.py            # HTTP-level detection (fast)
    python benchmark_firingrange.py --deep     # + Chromium (DOM v6, headless verify)
    python benchmark_firingrange.py --only=reflected,escaped
"""
import json
import logging
import os
import sys
from urllib.parse import urlparse, unquote

logging.disable(logging.CRITICAL)

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)

import fr_server  # noqa: E402
import xss_grenade as xg  # noqa: E402

SEV = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ACTIONABLE = 3  # >= high

# Public payload shapes for the scanner to work with. The engine also
# synthesises its own context-aware payloads on top of these.
PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    '"><svg onload=alert(1)>',
    "'><svg onload=alert(1)>",
    '"><script>alert(1)</script>',
    "</script><svg onload=alert(1)>",
    "</textarea><svg onload=alert(1)>",
    "</title><svg onload=alert(1)>",
    "</style><svg onload=alert(1)>",
    "--><svg onload=alert(1)>",
    "';alert(1)//",
    '";alert(1)//',
    "alert(1)",
    "javascript:alert(1)",
    " onmouseover=alert(1) ",
]


def load_labels(path=None):
    path = path or os.path.join(_HERE, "fr_groundtruth.json")
    if not os.path.exists(path):
        sys.exit(f"missing ground truth: {path}\nRun:  python fr_oracle.py")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)["labels"]


def endpoint_of(url):
    """Map a finding URL back to its corpus endpoint path."""
    if not url:
        return None
    try:
        p = urlparse(unquote(str(url))).path
    except Exception:
        return None
    parts = [x for x in p.split("/") if x]
    if len(parts) >= 3 and parts[0] == "reflected" and parts[1] == "parameter":
        return f"/reflected/parameter/{parts[2]}"
    if len(parts) >= 4 and parts[0] == "reflected" and parts[1] == "escapedparameter":
        return f"/reflected/escapedparameter/{parts[2]}/{parts[3]}"
    if len(parts) >= 3 and parts[0] == "address":
        return f"/address/{parts[1]}/{parts[2]}"
    return None


# A hit's severity is NOT reliably top-level: static-js / dom-v6 / PP hits carry
# it inside their typed sub-finding (e.g. static_js_finding.severity ==
# "critical" while hit["severity"] is absent). Reading only the top level scores
# every such finding as severity 0 and collapses STRICT recall to ~zero.
_SUBFINDING_KEYS = ("static_js_finding", "dom_v6_finding", "dom_finding",
                    "proto_pollution_finding", "mutation_xss_finding",
                    "dom_clobbering_finding", "postmessage_finding")


def hit_severity(hit):
    """Best severity a hit carries, top level or inside its sub-finding."""
    best = str(hit.get("severity") or "").lower()
    rank = SEV.get(best, 0)
    for k in _SUBFINDING_KEYS:
        d = hit.get(k)
        if isinstance(d, dict):
            r = SEV.get(str(d.get("severity") or "").lower(), 0)
            if r > rank:
                rank, best = r, str(d.get("severity")).lower()
    return best, rank


def hit_fp_risk(hit):
    if hit.get("fp_risk") is True:
        return True
    for k in _SUBFINDING_KEYS:
        d = hit.get(k)
        if isinstance(d, dict) and d.get("fp_risk") is True:
            return True
    return False


def _iter_finding_urls(hit):
    """Every URL-ish field a finding may carry."""
    yield hit.get("url")
    for k in ("page_url", "target_url", "location", "endpoint"):
        if hit.get(k):
            yield hit[k]
    for sub in _SUBFINDING_KEYS:
        d = hit.get(sub)
        if isinstance(d, dict):
            for k in ("file", "url", "page_url"):
                if d.get(k):
                    yield d[k]


def run(deep=False, only=None, store_path=None, batch=0):
    labels = load_labels()
    base, srv = fr_server.start(0)
    eps = [e for e in fr_server.endpoints() if not only or e[0] in only]
    wanted = {p for _, p, _ in eps}
    print(f"target  = {base}")
    print(f"corpus  = {len(eps)} endpoints  ({'DEEP: +Chromium' if deep else 'LEAN: HTTP-level'})")

    store = store_path or os.path.join(_HERE, "fr_evidence.jsonl")
    try:
        os.remove(store)
    except OSError:
        pass

    raw_hits = []
    _keys = ["on_hit", "on_log", "on_csp", "on_waf", "on_crawler_progress",
             "on_crawler_done", "on_progress", "on_phase", "on_finding",
             "on_status", "on_error", "on_done"]
    cb = {k: (lambda *a, **kw: None) for k in _keys}
    cb["on_hit"] = lambda d: raw_hits.append(d)

    def _scan(target, max_pages):
        xg.run_scan(
            target=target, payloads=PAYLOADS, workers=8, timeout=6.0,
            sleep_between=0.0, verify_ssl=False, limit_urls=None,
            limit_payloads=None, early_exit=False, canary=True,
            marker_enabled=True, marker_param="xss", verbose=False,
            report_path=None, json_report=None, rotate_ua=False, user_agents=[],
            proxies={}, follow_redirects=True,
            crawl_depth=1, crawl_max_pages=max_pages,
            enable_context_scan=True, static_js=True,
            dom_v6_taint=deep, headless_verify=deep, dom_dynamic=deep,
            warmup_origin=False, evidence_store_path=store, callbacks=cb)

    if batch:
        # Several page-level phases cap how many pages they will process
        # (MAX_DOM_V6_PAGES = 25 at xss_grenade.py:19696). Crawling all 311
        # endpoints in one pass therefore leaves most of the corpus without DOM
        # analysis and measures the cap rather than the detector. Scanning
        # batch index pages keeps each phase's budget non-binding.
        chunks = fr_server.batches(batch, only)
        suffix = "/" + ",".join(sorted(only)) if only else ""
        print(f"mode    = BATCHED: {len(chunks)} scans of <= {batch} endpoints"
              f" (engine page caps kept non-binding)")
        for i, ch in enumerate(chunks):
            print(f"  batch {i + 1}/{len(chunks)} ({len(ch)} endpoints)", flush=True)
            _scan(f"{base.rstrip('/')}/batch/{batch}/{i}{suffix}", batch + 5)
    else:
        _scan(base, 400)
    srv.shutdown()

    # ── collect what the scanner said, per endpoint ──
    best = {}  # endpoint -> max actionable severity seen

    def _record(ep, sev, fp_risk):
        if ep is None or ep not in wanted:
            return
        s = SEV.get(str(sev).lower(), 0)
        cur = best.setdefault(ep, {"any": False, "act": 0})
        cur["any"] = True
        if fp_risk is not True:
            cur["act"] = max(cur["act"], s)

    ev = []
    try:
        with open(store, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    ev.append(json.loads(line))
    except Exception:
        pass
    for r in ev:
        v = r.get("verdict", {}) or {}
        _record(endpoint_of((r.get("target", {}) or {}).get("url", "")),
                v.get("severity"), v.get("fp_risk"))
    for h in raw_hits:
        sev, _rank = hit_severity(h)
        fpr = hit_fp_risk(h)
        for u in _iter_finding_urls(h):
            ep = endpoint_of(u)
            if ep:
                _record(ep, sev, fpr)
                break

    # ── score ──
    fams = ("reflected", "escaped", "address")
    rows = {f: {"tp": [], "fn": [], "fp": [], "tn": [],
                "s_tp": [], "s_fn": [], "s_fp": [], "s_tn": [],
                "noise": []} for f in fams}

    for kind, path, _inj in eps:
        lab = labels.get(path)
        if lab is None:
            continue
        vuln = lab["vulnerable"]
        got = best.get(path, {"any": False, "act": 0})
        lenient_hit = got["any"]
        strict_hit = got["act"] >= ACTIONABLE
        r = rows[kind]
        if vuln:
            (r["tp"] if lenient_hit else r["fn"]).append(path)
            (r["s_tp"] if strict_hit else r["s_fn"]).append(path)
        else:
            # NOTE both conventions threshold a false positive at >= high
            # without fp_risk, so the FP column is identical in each; only
            # recall differs. `noise` is the separate, softer question: how
            # often does a SAFE endpoint produce any finding at all (incl.
            # info/low)? That is the report clutter a user actually wades
            # through, even when it is not a wrong verdict.
            (r["fp"] if strict_hit else r["tn"]).append(path)
            (r["s_fp"] if strict_hit else r["s_tn"]).append(path)
            if lenient_hit:
                r["noise"].append(path)

    def pct(a, b):
        return f"{(100.0 * a / b):5.1f}%" if b else "   n/a"

    print("\n" + "=" * 76)
    print("XSS GRENADE vs GOOGLE FIRING RANGE  —  independent corpus,")
    print("                                       browser-verified ground truth")
    print("=" * 76)

    tot = {k: 0 for k in ("tp", "fn", "fp", "tn",
                          "s_tp", "s_fn", "s_fp", "s_tn", "noise")}
    for f in fams:
        r = rows[f]
        if not any(len(r[k]) for k in r):
            continue
        nv = len(r["tp"]) + len(r["fn"])
        ns = len(r["fp"]) + len(r["tn"])
        for k in tot:
            tot[k] += len(r[k])
        print(f"\n── {f.upper()}  ({nv} vulnerable / {ns} safe) ──")
        print(f"   LENIENT  recall {len(r['tp'])}/{nv} ({pct(len(r['tp']), nv)})"
              f"   |  FP {len(r['fp'])}/{ns} ({pct(len(r['fp']), ns)})")
        print(f"   STRICT   recall {len(r['s_tp'])}/{nv} ({pct(len(r['s_tp']), nv)})"
              f"   |  FP {len(r['s_fp'])}/{ns} ({pct(len(r['s_fp']), ns)})")
        print(f"   noise    {len(r['noise'])}/{ns} ({pct(len(r['noise']), ns)}) "
              f"safe endpoints produced SOME finding (incl. info/low)")
        if r["fn"]:
            print(f"   missed  : {sorted(r['fn'])[:8]}{' …' if len(r['fn']) > 8 else ''}")
        if r["fp"]:
            print(f"   false + : {sorted(r['fp'])[:8]}{' …' if len(r['fp']) > 8 else ''}")

    def prf(tp, fn, fp):
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        return prec, rec, f1

    print("\n" + "=" * 76)
    print("TOTALS")
    print("=" * 76)
    for tag, (tp, fn, fp, tn) in (
            ("LENIENT", (tot["tp"], tot["fn"], tot["fp"], tot["tn"])),
            ("STRICT ", (tot["s_tp"], tot["s_fn"], tot["s_fp"], tot["s_tn"]))):
        prec, rec, f1 = prf(tp, fn, fp)
        print(f"  {tag}  TP {tp:3d}  FN {fn:3d}  FP {fp:3d}  TN {tn:3d}"
              f"   |  precision {prec*100:5.1f}%  recall {rec*100:5.1f}%  F1 {f1*100:5.1f}%")
    n_safe = tot["fp"] + tot["tn"]
    print(f"  NOISE    {tot['noise']}/{n_safe} safe endpoints produced some finding"
          f" ({pct(tot['noise'], n_safe).strip()}) — report clutter, not wrong verdicts")
    print("=" * 76)

    out = os.path.join(_HERE, "fr_result.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"deep": deep, "totals": tot,
                   "rows": {f: {k: v for k, v in rows[f].items()} for f in fams}},
                  fh, indent=1)
    print(f"  detail -> {out}")
    return 0


if __name__ == "__main__":
    only, batch = None, 0
    for a in sys.argv[1:]:
        if a.startswith("--only="):
            only = set(a.split("=", 1)[1].split(","))
        elif a.startswith("--batch="):
            batch = int(a.split("=", 1)[1])
    sys.exit(run(deep="--deep" in sys.argv, only=only, batch=batch))
