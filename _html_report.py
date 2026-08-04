"""
_html_report.py — Client-ready HTML report for XSS Grenade (v10.16).

Takes the same report dict written to JSON and renders a single, self-
contained .html file (inline CSS, no external assets → works offline, safe
to email / attach to a ticket). Design goals:

  • Triage-first. Severity summary up top (critical→info), then findings
    grouped by severity, each with endpoint, parameter, context, evidence,
    and remediation guidance.
  • Safe by construction. ALL dynamic values are HTML-escaped — a report
    about XSS must never itself execute injected payloads when opened.
  • Self-contained. One file, inline styles, no CDN/JS deps. Renders in any
    browser, prints cleanly to PDF.
  • Forward-compatible. Reads the report dict defensively (missing keys =
    skipped section), so new finding categories don't break old rendering.

Public API:
    build_html_report(report: dict) -> str
    write_html_report(report: dict, path: str) -> None
"""

from __future__ import annotations

import html
import time
from typing import Any, Dict, List, Optional


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#2563eb",
    "info":     "#6b7280",
}

# Per-context remediation guidance. Keyed by substring match on the finding's
# context so new contexts fall back to a generic XSS note rather than nothing.
_REMEDIATION = [
    ("script", "Reflected inside a &lt;script&gt; block. Never place "
                "untrusted data in JS context; use JSON-encoding + "
                "Content-Security-Policy with nonce/strict-dynamic."),
    ("event",  "Reflected in an event-handler attribute. Remove inline "
                "handlers; bind via addEventListener over trusted data."),
    ("url",    "Reflected in a URL/href/src. Validate scheme (allow only "
                "http/https), reject javascript:/data:; URL-encode values."),
    ("attr",   "Reflected in an HTML attribute. Quote attributes and "
                "HTML-attribute-encode the value; prefer allow-listing."),
    ("path",   "Reflected from a URL path segment. Encode path-derived "
                "output (e.g. in 404 / breadcrumb pages) before rendering."),
    ("cookie", "Reflected from a cookie value. HTML-encode cookie-derived "
                "output; set HttpOnly where the cookie isn't needed in JS."),
    ("cors",   "Permissive CORS. Reflect Origin only against an allow-list; "
                "never combine Access-Control-Allow-Credentials with "
                "Access-Control-Allow-Origin: *."),
    ("ssrf",   "Server-Side Request Forgery. Allow-list outbound hosts, "
                "block link-local/metadata ranges (169.254.169.254), and "
                "disable unused URL schemes."),
    ("crlf",   "CRLF / header injection. Reject CR/LF in header-bound "
                "values; use a framework API that encodes headers."),
    ("vulnerable-library", "Outdated dependency with a known CVE. Upgrade to "
                "the patched version listed in the finding evidence."),
    ("dom",    "DOM-based XSS. Avoid sinks (innerHTML, document.write, eval); "
                "use textContent / sanitizer (DOMPurify) on untrusted data."),
    ("template", "Template/SSTI. Don't render user input as a template; use "
                "auto-escaping template engines and pass data, not code."),
]
_GENERIC_REMEDIATION = (
    "Reflected XSS. Context-encode all untrusted output, prefer allow-list "
    "validation, and deploy a strict Content-Security-Policy as defense in "
    "depth."
)


def _esc(v: Any) -> str:
    """HTML-escape any value. CRITICAL: every dynamic value in the report
    passes through here so a payload can never execute when the report is
    opened in a browser."""
    return html.escape(str(v if v is not None else ""), quote=True)


def _resolve_severity(hit: dict) -> str:
    for key in ("severity", "gate_severity"):
        v = (hit.get(key) or "").strip().lower()
        if v in _SEVERITY_ORDER:
            return v
    # v10.16: sladěno s engine _resolve_severity + context_engine — kritické
    # kontexty (JS exec / code-exec sink / tag breakout) dostanou critical,
    # ne strop na high. Pro nálezy bez explicitní severity / gate_severity.
    ctx = (hit.get("context") or "").lower()
    evidence = (hit.get("evidence") or "").lower()
    sink = (hit.get("sink") or hit.get("sink_name") or "").lower()
    blob = f"{ctx} {evidence} {sink}"
    _CRIT = (
        "script_body", "script-body", "code-exec", "code_exec",
        "eval", "function(", "document.write", "settimeout", "setinterval",
        "innerhtml", "outerhtml", "template-injection", "template_injection",
        "ssti", "proto-pollution-chain", "prototype-pollution",
        "unquoted", "tag_injection", "tag-injection", "tag breakout",
        "dangling-markup",
    )
    if any(s in blob for s in _CRIT):
        return "critical"
    _HIGH = (
        "script", "event", "stored", "dom-v6", "dom-dynamic", "dom_dynamic",
        "static-js-taint", "taint", "postmessage", "jsonp", "svg-xml",
        "javascript:", "href", "src=", "attr_breakout", "attribute breakout",
    )
    if any(s in blob for s in _HIGH):
        return "high"
    if "url" in blob or "attr" in blob or "html" in blob:
        return "medium"
    return "medium"


def _remediation_for(context: str) -> str:
    c = (context or "").lower()
    for key, text in _REMEDIATION:
        if key in c:
            return text
    return _GENERIC_REMEDIATION


def _finding_rows(findings: List[dict]) -> str:
    """Render findings grouped by severity (critical first)."""
    by_sev: Dict[str, List[dict]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        by_sev[_resolve_severity(f)].append(f)

    blocks = []
    for sev in _SEVERITY_ORDER:
        group = by_sev[sev]
        if not group:
            continue
        color = _SEVERITY_COLOR[sev]
        cards = []
        for f in group:
            endpoint = f.get("endpoint") or f.get("url", "")
            param = f.get("param", "")
            ctx = f.get("context", "")
            payload = f.get("payload", "")
            evidence = f.get("evidence", "")
            source = f.get("source", "")
            dup = f.get("duplicate_count", 0)
            # v10.26: poctivý FP-risk label — ko-lokační/neověřené nálezy nesou
            # fp_risk=True + potential_severity + fp_reason. Klient MUSÍ vidět,
            # že tohle není potvrzený TP, ale kandidát k ruční verifikaci.
            fp_risk = bool(f.get("fp_risk"))
            pot_sev = f.get("potential_severity")
            fp_reason = f.get("fp_reason") or f.get("downgrade_reason") or ""
            fp_badge = ""
            if fp_risk:
                pot_txt = (f" &middot; potential {_esc(pot_sev)}" if pot_sev else "")
                fp_badge = (f'<span class="fpbadge">&#9888; FP-RISK / UNVERIFIED'
                            f'{pot_txt}</span>')
            fp_reason_html = (
                f'<tr><th>FP risk</th><td class="fpreason">{_esc(fp_reason)}</td></tr>'
                if fp_risk and fp_reason else "")
            dup_html = ""
            if dup:
                dup_urls = f.get("duplicate_urls", []) or []
                sample = "".join(
                    f"<li><code>{_esc(u)}</code></li>" for u in dup_urls[:5])
                dup_html = (
                    f'<div class="dup">+{_esc(dup)} more affected URL(s)'
                    + (f'<ul>{sample}</ul>' if sample else '') + '</div>')
            # v10.48: scorer blok — confidence + doporučená severita + důvody
            score = f.get("score") or {}
            score_html = ""
            if score:
                _conf = score.get("score")
                conf_txt = (f"{round(_conf * 100)}%"
                            if isinstance(_conf, (int, float)) else "—")
                rec_sev = score.get("recommended_severity", "")
                sv = score.get("scorer_version", "")
                reasons = score.get("reasons") or []
                reasons_html = "".join(f"<li>{_esc(r)}</li>" for r in reasons[:8])
                rec_html = (f' &middot; doporučená severita: <strong>{_esc(rec_sev)}</strong>'
                            if rec_sev else "")
                sv_html = f' &middot; scorer {_esc(sv)}' if sv else ""
                score_html = (
                    f'<tr><th>Confidence (scorer)</th><td>'
                    f'<strong>{conf_txt}</strong>{rec_html}{sv_html}</td></tr>'
                    + (f'<tr><th>Scorer reasons</th><td>'
                       f'<ul class="reasons">{reasons_html}</ul></td></tr>'
                       if reasons_html else ""))
            # v10.48: evidence chain — auditovatelná stopa, co nález prokázalo
            chain = f.get("evidence_chain") or []
            chain_html = ""
            if chain:
                steps = "".join(f"<li>{_esc(step)}</li>" for step in chain)
                chain_html = (f'<tr><th>Evidence chain</th><td>'
                              f'<ol class="evchain">{steps}</ol></td></tr>')
            cards.append(f"""
        <div class="finding{' fp-risk' if fp_risk else ''}">
          <div class="finding-head">
            <span class="ctx">{_esc(ctx or 'xss')}</span>
            <code class="ep">{_esc(endpoint)}</code>
            {fp_badge}
          </div>
          <table class="kv">
            <tr><th>Parameter</th><td><code>{_esc(param)}</code></td></tr>
            <tr><th>Source</th><td>{_esc(source)}</td></tr>
            {f'<tr><th>Payload</th><td><code>{_esc(payload)}</code></td></tr>' if payload else ''}
            {f'<tr><th>Evidence</th><td><code>{_esc(evidence)}</code></td></tr>' if evidence else ''}
            {score_html}
            {chain_html}
            {fp_reason_html}
          </table>
          <div class="remediation"><strong>Remediation:</strong> {_remediation_for(ctx)}</div>
          {dup_html}
        </div>""")
        blocks.append(f"""
      <section class="sev-group">
        <h2 style="border-left:6px solid {color}"><span style="color:{color}">&#9632;</span>
          {sev.upper()} <span class="count">({len(group)})</span></h2>
        {''.join(cards)}
      </section>""")
    return "".join(blocks) if blocks else (
        '<p class="empty">No confirmed findings.</p>')


def build_html_report(report: Dict[str, Any]) -> str:
    """Render the full report dict to a self-contained HTML string."""
    target = report.get("target", "(unknown)")
    summary = report.get("summary", {}) or {}
    by_sev = summary.get("by_severity", {}) or {}
    total = summary.get("total", report.get("findings_count", 0))
    total_raw = summary.get("total_raw", total)

    # Prefer deduped findings for display; fall back to raw findings.
    findings = report.get("findings_deduped") or report.get("findings", []) or []

    # Severity summary chips
    chips = []
    for sev in _SEVERITY_ORDER:
        n = by_sev.get(sev, 0)
        color = _SEVERITY_COLOR[sev]
        chips.append(
            f'<div class="chip" style="border-color:{color}">'
            f'<span class="chip-n" style="color:{color}">{_esc(n)}</span>'
            f'<span class="chip-l">{sev}</span></div>')

    # Library CVE findings get their own table (high signal for triage)
    cve_rows = ""
    for c in report.get("library_cve_findings", []) or []:
        cves = ", ".join(
            x.get("cve", "") for x in c.get("matched_cves", []))
        kev = " &#9888; exploited in wild" if c.get("exploited_in_wild") else ""
        cve_rows += (
            f"<tr><td><code>{_esc(c.get('library'))}</code></td>"
            f"<td>{_esc(c.get('version'))}</td>"
            f"<td>{_esc(cves)}{kev}</td>"
            f"<td>{_esc(c.get('max_severity'))}</td></tr>")
    cve_section = (f"""
    <section>
      <h2>Vulnerable libraries / frameworks</h2>
      <table class="cve">
        <tr><th>Library</th><th>Version</th><th>CVE(s)</th><th>Severity</th></tr>
        {cve_rows}
      </table>
    </section>""" if cve_rows else "")

    generated = time.strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>XSS Grenade Report — {_esc(target)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
    margin: 0; background: #0f1115; color: #e5e7eb; line-height: 1.5; }}
  .wrap {{ max-width: 960px; margin: 0 auto; padding: 32px 20px 64px; }}
  header h1 {{ margin: 0 0 4px; font-size: 22px; }}
  header .meta {{ color: #9ca3af; font-size: 13px; margin-bottom: 24px; }}
  header .meta code {{ color: #d1d5db; }}
  .chips {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 0 0 28px; }}
  .chip {{ border: 2px solid; border-radius: 10px; padding: 10px 16px; min-width: 86px;
    text-align: center; background: #161922; }}
  .chip-n {{ display: block; font-size: 26px; font-weight: 700; }}
  .chip-l {{ display: block; font-size: 11px; letter-spacing: 1px; text-transform: uppercase; color: #9ca3af; }}
  h2 {{ font-size: 16px; padding: 6px 0 6px 12px; margin: 28px 0 12px; }}
  h2 .count {{ color: #9ca3af; font-weight: 400; font-size: 13px; }}
  .finding {{ background: #161922; border: 1px solid #262b36; border-radius: 10px;
    padding: 14px 16px; margin-bottom: 12px; }}
  .finding-head {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 8px; }}
  .ctx {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #9ca3af;
    background: #0f1115; border: 1px solid #262b36; border-radius: 6px; padding: 2px 8px; }}
  .fpbadge {{ font-size: 10.5px; text-transform: uppercase; letter-spacing: .5px;
    color: #fde68a; background: #2a230b; border: 1px solid #a16207; border-radius: 6px;
    padding: 2px 8px; font-weight: 600; }}
  .finding.fp-risk {{ border-left: 3px solid #a16207; }}
  .fpreason {{ color: #fcd34d; font-size: 12.5px; }}
  .reasons {{ margin: 0; padding-left: 18px; font-size: 12.5px; color: #cbd5e1; }}
  .evchain {{ margin: 0; padding-left: 20px; font-size: 12.5px; color: #a7f3d0; }}
  .evchain li {{ margin: 2px 0; }}
  .ep {{ color: #93c5fd; word-break: break-all; }}
  table.kv {{ width: 100%; border-collapse: collapse; margin: 4px 0; }}
  table.kv th {{ text-align: left; width: 110px; color: #9ca3af; font-weight: 500;
    vertical-align: top; padding: 3px 8px 3px 0; font-size: 13px; }}
  table.kv td {{ padding: 3px 0; word-break: break-all; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px;
    background: #0f1115; padding: 1px 5px; border-radius: 4px; }}
  .remediation {{ margin-top: 8px; padding: 8px 10px; background: #11261c;
    border-left: 3px solid #16a34a; border-radius: 4px; font-size: 13px; color: #bbf7d0; }}
  .dup {{ margin-top: 8px; font-size: 12px; color: #9ca3af; }}
  .dup ul {{ margin: 4px 0 0; padding-left: 18px; }}
  table.cve {{ width: 100%; border-collapse: collapse; background: #161922;
    border: 1px solid #262b36; border-radius: 8px; overflow: hidden; }}
  table.cve th, table.cve td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #262b36; font-size: 13px; }}
  table.cve th {{ color: #9ca3af; background: #11141b; }}
  .empty {{ color: #9ca3af; }}
  footer {{ margin-top: 40px; color: #6b7280; font-size: 12px; border-top: 1px solid #262b36; padding-top: 16px; }}
  @media print {{ body {{ background: #fff; color: #000; }} .finding, .chip, table.cve {{ background: #fff; }} }}
</style></head>
<body><div class="wrap">
  <header>
    <h1>XSS Grenade — Security Report</h1>
    <div class="meta">Target: <code>{_esc(target)}</code> &nbsp;•&nbsp;
      Generated: {_esc(generated)} &nbsp;•&nbsp;
      {_esc(total)} unique finding(s){f' (from {_esc(total_raw)} raw)' if total_raw != total else ''}</div>
  </header>
  <div class="chips">{''.join(chips)}</div>
  {cve_section}
  <section>
    <h2 style="padding-left:0;border:0">Findings</h2>
    {_finding_rows(findings)}
  </section>
  <footer>Generated by XSS Grenade. This report is for authorized security
    testing only. All values are HTML-escaped; payloads shown are inert.</footer>
</div></body></html>"""


def write_html_report(report: Dict[str, Any], path: str) -> None:
    """Render and write the HTML report to `path`."""
    htmltext = build_html_report(report)
    with open(path, "w", encoding="utf-8") as f:
        f.write(htmltext)
