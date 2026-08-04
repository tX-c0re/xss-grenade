"""
_sarif_report.py — SARIF 2.1.0 export pro XSS Grenade (v10.26).

Modul dříve v distribuci chyběl (import byl v try/except → _SARIF_AVAILABLE=
False, --sarif jen zalogoval "not available"). Doplněn s PLNOU podporou
fp_risk poctivého labelu.

Klíčové principy:
  - severity → SARIF level: critical/high=error, medium=warning, low/info=note.
    Nálezy s fp_risk=True jsou info/low → "note" (NE error) — neověřený
    kandidát se nehlásí jako potvrzená chyba.
  - fp_risk / potential_severity / fp_reason jdou do result.properties, ať
    je downstream (GitHub code scanning, DefectDojo, …) vidí a může filtrovat.
  - partialFingerprints["xssg/v1"] = stabilní fingerprint (stejná identita
    napříč běhy) pro deduplikaci v SARIF konzumentech.

Stdlib-only.
"""
from __future__ import annotations

import json
import hashlib
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, parse_qsl

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# severity → SARIF level
_LEVEL = {
    "critical": "error", "high": "error",
    "medium": "warning",
    "low": "note", "info": "note", "informational": "note",
}

# kategorie report_dictu, které nejsou seznamy nálezů
_NON_FINDING_KEYS = {
    "target", "csp_analysis", "findings_count", "summary",
    "findings_deduped", "headless_verdicts", "emit_stats", "timestamp",
    # v10.80: blind_xss_injections is a list of PLANTED probes awaiting an
    # out-of-band callback — telemetry, NOT confirmed findings. OOB-confirmed
    # hits arrive separately via _emit_hit → findings. Emitting probes as SARIF
    # results produced one phantom 'note' per injected payload (FP + count
    # inflation that CI/code-scanning ingests).
    "blind_xss_injections",
    # v10.80: library_cve_findings are ALSO emitted via _emit_hit (so they are
    # already in findings_deduped and turned into results by the first loop).
    # Leaving them here double-counted every vulnerable-library finding and
    # mis-levelled the duplicate to 'note'.
    "library_cve_findings",
}


def _strip_url_dynamic(url: str) -> str:
    if not url:
        return ""
    try:
        sp = urlsplit(url)
        base = f"{sp.scheme}://{sp.netloc}{sp.path}"
        names = sorted({k for k, _ in parse_qsl(sp.query, keep_blank_values=True)})
        if names:
            base += "?" + "&".join(names)
        return base
    except Exception:
        return url


def _first(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if isinstance(d, dict) and k in d and d[k] is not None:
            return d[k]
    return default


def _flatten_nested(f: Dict[str, Any]) -> Dict[str, Any]:
    """Sloučí vnořené *_finding detail dicty (top-level vyhrává) — fp_risk
    se nesmí ztratit, viz _finding_store."""
    out = dict(f)
    for k, v in list(f.items()):
        if k.endswith("_finding") and isinstance(v, dict):
            for dk, dv in v.items():
                out.setdefault(dk, dv)
    return out


def _fingerprint(f: Dict[str, Any], kind: str) -> str:
    url = _first(f, "url", "endpoint", "test_url", default="")
    param = _first(f, "param", "source_origin", default="")
    ctx = _first(f, "context", "ti_context", default="")
    sink = "|".join(str(x) for x in (
        _first(f, "source_file", "gadget_file", "file", default=""),
        _first(f, "source_line", "gadget_line", "line", default=""),
        _first(f, "cwe", "cwe_hint", default=""),
    ))
    basis = "\x1f".join([kind, _strip_url_dynamic(str(url)), str(param), str(ctx), sink])
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:32]


def _result_from_finding(f: Dict[str, Any], category: str) -> Optional[Dict[str, Any]]:
    if not isinstance(f, dict):
        return None
    f = _flatten_nested(f)
    sev = str(_first(f, "severity", default="info")).lower()
    level = _LEVEL.get(sev, "note")
    fp_risk = bool(f.get("fp_risk"))
    pot_sev = _first(f, "potential_severity", "original_severity", default=None)
    fp_reason = _first(f, "fp_reason", "downgrade_reason", default=None)
    url = _first(f, "url", "endpoint", "test_url", default="") or ""
    param = _first(f, "param", default="") or ""
    ctx = _first(f, "context", "ti_context", default="") or ""
    kind = _first(f, "kind", default=category) or category
    cwe = _first(f, "cwe", "cwe_hint", default=None)

    # message: fp_risk prefix dělá neověřenost viditelnou i v plain textu
    prefix = ""
    if fp_risk:
        prefix = (f"[FP-RISK / UNVERIFIED"
                  + (f", potential {pot_sev}" if pot_sev else "") + "] ")
    desc = _first(f, "description", "evidence", default="") or ""
    msg = (f"{prefix}{kind} @ {url}"
           + (f" (param: {param})" if param else "")
           + (f" — {desc}" if desc else ""))

    props: Dict[str, Any] = {
        "severity": sev,
        "detector": category,
        "context": ctx,
        "fp_risk": fp_risk,
    }
    if pot_sev:
        props["potential_severity"] = pot_sev
    if fp_reason:
        props["fp_reason"] = fp_reason
    if fp_risk:
        # security-severity nehlásíme vysoko u neověřených (GitHub code scanning
        # to čte) — ponecháme nízké, ať se nepromuje do "error" dashboardů.
        props["unverified"] = True

    result: Dict[str, Any] = {
        "ruleId": f"xssg/{str(kind).replace(' ', '_')}",
        "level": level,
        "message": {"text": msg[:2000]},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": url or "unknown"},
            }
        }],
        "partialFingerprints": {"xssg/v1": _fingerprint(f, str(kind))},
        "properties": props,
    }
    return result


def build_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    """Sestaví SARIF 2.1.0 dokument z report_dictu."""
    results: List[Dict[str, Any]] = []
    rule_ids: Dict[str, Dict[str, Any]] = {}

    # primárně deduped findings (jako HTML report), jinak všechny kategorie
    findings = report.get("findings_deduped") or report.get("findings") or []
    for f in findings:
        r = _result_from_finding(f, "findings")
        if r:
            results.append(r)
            rule_ids.setdefault(r["ruleId"], {"id": r["ruleId"]})

    # + ostatní per-kategorie listy (PP, template, static_js, …)
    for key, value in report.items():
        if key in _NON_FINDING_KEYS or key in ("findings", "findings_deduped"):
            continue
        if not isinstance(value, list):
            continue
        for f in value:
            r = _result_from_finding(f, key)
            if r:
                results.append(r)
                rule_ids.setdefault(r["ruleId"], {"id": r["ruleId"]})

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "XSS Grenade",
                    "informationUri": "https://tx-core.com",
                    "rules": list(rule_ids.values()),
                }
            },
            "results": results,
        }],
    }


def write_sarif_report(report: Dict[str, Any], path: str) -> None:
    doc = build_sarif(report)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
