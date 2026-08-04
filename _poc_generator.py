"""
_poc_generator.py — Auto-PoC export for XSS Grenade (v10.58).

Turns the scan's confirmed findings into a single, self-contained,
bug-bounty-ready PoC bundle (`.html`). For each confirmed finding it emits:

  • a ready exploit artifact — a "Launch" link (GET / DOM) or an auto-submit
    form (POST/stored) that fires the payload against the LIVE target when the
    tester clicks it (NOT on page load);
  • a copy-pasteable `curl` reproduction;
  • a short Markdown writeup (title / severity / steps / impact) to paste into
    a report.

SAFETY BY CONSTRUCTION: the bundle itself is inert. EVERY dynamic value is
HTML-escaped (payloads shown as text, never executed when the bundle is opened),
and nothing auto-navigates or auto-submits — the tester must click. Escaping is
display-only: a launched link/form still sends the RAW payload to the target
(the browser decodes the escaped href/attribute on click).

Public API:
    build_poc_bundle(report: dict) -> str
    write_poc_bundle(report: dict, path: str) -> int   # returns PoC count
"""

from __future__ import annotations

import html
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


_MAX_POCS = 300  # cap bundle size on huge scans

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_COLOR = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706",
              "low": "#2563eb", "info": "#6b7280"}


def _esc(v: Any) -> str:
    return html.escape(str(v if v is not None else ""), quote=True)


def _first(d: Dict[str, Any], *keys: str, default: Any = "") -> Any:
    for k in keys:
        if isinstance(d, dict) and d.get(k) not in (None, ""):
            return d[k]
    return default


def _severity(f: Dict[str, Any]) -> str:
    for k in ("severity", "gate_severity", "rich_severity"):
        v = str(f.get(k) or "").strip().lower()
        if v in _SEV_ORDER:
            return v
    return "medium"


def _method(f: Dict[str, Any]) -> str:
    """get | post | dom — how the payload is delivered."""
    m = str(_first(f, "method", "http_method", default="")).lower()
    src = str(_first(f, "source", "kind", default="")).lower()
    ctx = str(_first(f, "context", default="")).lower()
    url = str(_first(f, "url", "test_url", "action", default=""))
    if "post" in m or "stored" in src or "form" in src:
        return "post"
    if ("dom" in src or "fragment" in src or "dom" in ctx or "fragment" in ctx
            or "#" in url):
        return "dom"
    return "get"


def _exploit_url(f: Dict[str, Any]) -> str:
    """The URL that carries the payload. For reflected/context/DOM findings the
    finding's `url` is ALREADY the built test URL — use it verbatim (don't
    re-encode, which would diverge from what was actually sent). Only inject
    param=payload when the URL doesn't already carry that parameter."""
    url = str(_first(f, "url", "test_url", "view_url", "action", default=""))
    param = str(_first(f, "param", default=""))
    payload = str(_first(f, "payload", default=""))
    if not url:
        return ""
    if not param or not payload:
        return url
    try:
        sp = urlsplit(url)
        existing = dict(parse_qsl(sp.query, keep_blank_values=True))
        if param in existing:
            return url  # url IS the built test URL — keep its exact encoding
        q = list(parse_qsl(sp.query, keep_blank_values=True)) + [(param, payload)]
        return urlunsplit((sp.scheme, sp.netloc, sp.path,
                           urlencode(q, doseq=True), sp.fragment))
    except Exception:
        return url


def _norm_endpoint(u: str) -> str:
    """scheme://host/path — drop query + fragment so payload encoding differences
    don't break matching."""
    try:
        sp = urlsplit(u or "")
        return f"{sp.scheme}://{sp.netloc}{sp.path}"
    except Exception:
        return u or ""


def _curl(f: Dict[str, Any]) -> str:
    method = _method(f)
    if method == "post":
        action = str(_first(f, "action", "url", default=""))
        param = str(_first(f, "param", default="q"))
        payload = str(_first(f, "payload", default=""))
        # single-quote the whole arg; escape embedded single quotes for the shell
        arg = f"{param}={payload}".replace("'", "'\\''")
        return f"curl -sk '{action}' --data-urlencode '{arg}'"
    return f"curl -sk '{_exploit_url(f)}'"


def _poc_key(f: Dict[str, Any]) -> str:
    return "|".join([_method(f), _exploit_url(f),
                     str(_first(f, "param", default="")),
                     str(_first(f, "payload", default=""))])


def _confirmed_keys(report: Dict[str, Any]) -> set:
    """(endpoint, param) signatures the headless verifier proved EXECUTED with
    our canary (alert fired) — used to badge findings as browser-confirmed.
    Mirrors the engine's rule: executed AND the fired dialog carried our canary
    (method without 'no_canary')."""
    out = set()
    for v in (report.get("headless_verdicts") or []):
        if not isinstance(v, dict):
            continue
        if not (v.get("executed") or v.get("confirmed")):
            continue
        if "no_canary" in str(v.get("method") or ""):
            continue
        out.add((_norm_endpoint(_first(v, "url", "test_url", default="")),
                 str(v.get("param", ""))))
    return out


def _finding_confirmed(f: Dict[str, Any], keys: set) -> bool:
    return (_norm_endpoint(_first(f, "url", "action", "test_url", default="")),
            str(_first(f, "param", default=""))) in keys


def _collect(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Confirmed, PoC-able findings from the report dict, deduped."""
    buckets: List[Any] = []
    buckets += report.get("findings_deduped") or report.get("findings") or []
    buckets += report.get("open_redirect_findings") or []
    buckets += report.get("stored_roundtrip_findings") or []
    seen, out = set(), []
    for f in buckets:
        if not isinstance(f, dict):
            continue
        if not (_first(f, "url", "test_url", "action", default="")):
            continue
        k = _poc_key(f)
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
        if len(out) >= _MAX_POCS:
            break
    out.sort(key=lambda f: _SEV_ORDER.index(_severity(f))
             if _severity(f) in _SEV_ORDER else 99)
    return out


def _artifact_html(f: Dict[str, Any]) -> str:
    method = _method(f)
    if method == "post":
        action = _esc(_first(f, "action", "url", default=""))
        param = _esc(_first(f, "param", default="q"))
        payload = _esc(_first(f, "payload", default=""))
        # value attribute is escaped for display; the browser sends the RAW
        # payload when the tester submits.
        return (
            f'<form action="{action}" method="POST" target="_blank" '
            f'rel="noopener" class="pocform">'
            f'<input type="hidden" name="{param}" value="{payload}">'
            f'<button type="submit">▶ Launch POST PoC (new tab)</button>'
            f'</form>')
    url = _exploit_url(f)
    note = (' <span class="hint">(DOM / client-side — the payload lives in the '
            'URL fragment and never reaches the server)</span>'
            if method == "dom" else "")
    return (f'<a class="launch" href="{_esc(url)}" target="_blank" '
            f'rel="noopener">▶ Launch PoC (new tab)</a>{note}')


def _writeup_md(f: Dict[str, Any], confirmed: bool) -> str:
    sev = _severity(f).upper()
    ctx = _first(f, "context", default="reflected")
    param = _first(f, "param", default="?")
    method = _method(f).upper()
    steps = (f"Send a `{method}` request to the endpoint with `{param}` set to "
             f"the payload below and observe script execution in the response.")
    if method == "POST":
        steps = (f"Submit the form to the action URL with `{param}` set to the "
                 f"payload below; view the resulting page to observe execution.")
    badge = " (browser-confirmed: alert fired in headless Chromium)" if confirmed else ""
    return (
        f"### {sev} — {ctx} XSS in `{param}`{badge}\n"
        f"- **URL:** {_first(f, 'url', 'action', 'test_url', default='')}\n"
        f"- **Parameter:** {param}\n"
        f"- **Payload:** `{_first(f, 'payload', default='')}`\n"
        f"- **Steps:** {steps}\n"
        f"- **Impact:** Arbitrary JavaScript executes in a victim's session on "
        f"the target origin (session theft, action-on-behalf, credential "
        f"phishing).\n")


def build_poc_bundle(report: Dict[str, Any]) -> str:
    findings = _collect(report)
    confirmed_keys = _confirmed_keys(report)
    target = _esc(report.get("target", "(unknown)"))
    generated = time.strftime("%Y-%m-%d %H:%M:%S")

    cards = []
    for i, f in enumerate(findings, 1):
        confirmed = _finding_confirmed(f, confirmed_keys)
        sev = _severity(f)
        color = _SEV_COLOR.get(sev, "#6b7280")
        badge = ('<span class="cbadge">✓ BROWSER-CONFIRMED</span>'
                 if confirmed else "")
        cards.append(f"""
      <div class="poc">
        <div class="pochead">
          <span class="sev" style="background:{color}">{sev.upper()}</span>
          <span class="idx">#{i}</span>
          <code class="ep">{_esc(_first(f, 'url', 'action', 'test_url', default=''))}</code>
          {badge}
        </div>
        <table class="kv">
          <tr><th>Parameter</th><td><code>{_esc(_first(f, 'param', default=''))}</code></td></tr>
          <tr><th>Context</th><td>{_esc(_first(f, 'context', default=''))}</td></tr>
          <tr><th>Payload</th><td><code>{_esc(_first(f, 'payload', default=''))}</code></td></tr>
        </table>
        <div class="launchrow">{_artifact_html(f)}</div>
        <div class="lbl">curl reproduction</div>
        <pre class="curl">{_esc(_curl(f))}</pre>
        <div class="lbl">report writeup (Markdown)</div>
        <pre class="md">{_esc(_writeup_md(f, confirmed))}</pre>
      </div>""")

    body = "".join(cards) if cards else (
        '<p class="empty">No confirmed, PoC-able findings in this scan.</p>')

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>XSS Grenade — PoC bundle — {target}</title>
<style>
  body {{ font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif; margin:0;
    background:#0f1115; color:#e5e7eb; line-height:1.5; }}
  .wrap {{ max-width:960px; margin:0 auto; padding:28px 20px 64px; }}
  h1 {{ font-size:21px; margin:0 0 4px; }}
  .meta {{ color:#9ca3af; font-size:13px; margin-bottom:18px; }}
  .warn {{ background:#3a1d1d; border:1px solid #b91c1c; color:#fecaca;
    border-radius:8px; padding:10px 14px; font-size:13px; margin-bottom:22px; }}
  .poc {{ background:#161922; border:1px solid #262b36; border-radius:10px;
    padding:14px 16px; margin-bottom:14px; }}
  .pochead {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:8px; }}
  .sev {{ color:#fff; font-size:11px; font-weight:700; padding:2px 8px; border-radius:5px; }}
  .idx {{ color:#9ca3af; font-size:12px; }}
  .cbadge {{ color:#052e16; background:#22c55e; font-size:10.5px; font-weight:700;
    padding:2px 8px; border-radius:5px; }}
  .ep {{ color:#93c5fd; word-break:break-all; }}
  table.kv {{ width:100%; border-collapse:collapse; margin:4px 0; }}
  table.kv th {{ text-align:left; width:96px; color:#9ca3af; font-weight:500;
    vertical-align:top; padding:3px 8px 3px 0; font-size:13px; }}
  table.kv td {{ padding:3px 0; word-break:break-all; }}
  code {{ font-family:ui-monospace,Menlo,monospace; font-size:12.5px;
    background:#0f1115; padding:1px 5px; border-radius:4px; }}
  .launchrow {{ margin:10px 0; }}
  .launch, .pocform button {{ display:inline-block; background:#b91c1c; color:#fff;
    border:0; border-radius:6px; padding:8px 14px; font-size:13px; font-weight:600;
    cursor:pointer; text-decoration:none; }}
  .pocform {{ display:inline; }}
  .hint {{ color:#9ca3af; font-size:12px; }}
  .lbl {{ color:#9ca3af; font-size:11px; text-transform:uppercase; letter-spacing:1px;
    margin:10px 0 3px; }}
  pre {{ background:#0f1115; border:1px solid #262b36; border-radius:6px;
    padding:8px 10px; overflow:auto; font-size:12.5px; margin:0; white-space:pre-wrap;
    word-break:break-word; }}
  .empty {{ color:#9ca3af; }}
  footer {{ margin-top:36px; color:#6b7280; font-size:12px; border-top:1px solid #262b36; padding-top:14px; }}
</style></head>
<body><div class="wrap">
  <h1>XSS Grenade — PoC bundle</h1>
  <div class="meta">Target: <code>{target}</code> &nbsp;•&nbsp; Generated: {_esc(generated)}
    &nbsp;•&nbsp; {len(findings)} proof(s) of concept</div>
  <div class="warn"><strong>Authorized testing only.</strong> This bundle is inert
    on its own — payloads are shown as escaped text. A PoC only fires when YOU click
    “Launch”, which sends the real payload to the live target. Use only against
    systems you are permitted to test.</div>
  {body}
  <footer>Generated by XSS Grenade. Payloads are HTML-escaped for safe viewing.</footer>
</div></body></html>"""


def write_poc_bundle(report: Dict[str, Any], path: str) -> int:
    """Render + write the PoC bundle. Returns the number of PoCs written."""
    findings = _collect(report)
    htmltext = build_poc_bundle(report)
    with open(path, "w", encoding="utf-8") as f:
        f.write(htmltext)
    return len(findings)
