"""
_finding_store.py — Perzistenční vrstva nálezů pro ML / drift / triage.

Cíl (dle dohody s TX-C0RE):
    Ukládat KAŽDÝ nález na všech úrovních (info → critical), s plnou RAW
    evidencí (ne jen verdiktem severity), verzováním, stabilním fingerprintem
    a origin/retention flagem. Tohle je datový základ, na kterém pak stojí
    vážení (promote-vrstva) a později ML.

Design principy:
    1. NEZAHAZOVAT signál. Persistujeme i info/low — viditelnost driftu.
    2. Evidence (vstupní featury) je ODDĚLENÁ od verdiktu (výstup heuristiky).
       Kdybychom trénovali jen na verdiktu, naklonujeme heuristiku. Proto
       ukládáme i raw_finding verbatim a kurátorovanou sadu featur.
    3. Místo pro GROUND-TRUTH label (confirmed/dismissed/duplicate/exploited)
       — bez něj se nedá učit; s ním je každý záznam trénovací příklad.
    4. Stabilní fingerprint = stejná identita nálezu napříč běhy → detekce
       driftu (nový nález kvůli změně cíle vs. změně našeho kódu — rozliší
       pole scanner_version / detector_version).
    5. Data governance: origin (public/consented/client) + retence + flag
       contains_client_data. Navrženo do schématu teď, ne dolepeno později.

Formát: JSONL (1 záznam = 1 řádek). Append-only, stream-friendly pro ML
ingest. Stdlib-only (json, hashlib, uuid, time, datetime, os, threading, re).
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


SCHEMA_VERSION = "1.0"

# Kategorie z run_scan._report_dict, které NEjsou seznamy nálezů (přeskočit).
_NON_FINDING_KEYS = {
    "target", "csp_analysis", "findings_count", "summary",
    "findings_deduped", "headless_verdicts", "emit_stats", "timestamp",
}

# Mapování klíče v _report_dict → (kind, detector) pro normalizaci.
_CATEGORY_MAP: Dict[str, str] = {
    "findings":                     "reflected_or_web_vuln",
    "dom_static_findings":          "dom_xss_static",
    "dom_dynamic_findings":         "dom_xss_dynamic",
    "blind_xss_injections":         "blind_xss",
    "postmessage_static_findings":  "postmessage_static",
    "postmessage_dynamic_findings": "postmessage_dynamic",
    "websocket_static_findings":    "websocket_static",
    "websocket_dynamic_findings":   "websocket_dynamic",
    "mutation_xss_findings":        "mutation_xss",
    "template_injection_findings":  "template_injection",
    "dom_v6_findings":              "dom_xss_taint_v6",
    "static_js_findings":           "static_js_sink",
    "library_cve_findings":         "library_cve",
    "trusted_types_findings":       "trusted_types",
    "stored_roundtrip_findings":    "stored_xss_roundtrip",
    "proto_pollution_findings":     "proto_pollution",
    "dom_clobbering_findings":      "dom_clobbering",
    "ssr_hydration_findings":       "ssr_hydration",
    "csp_bypass_findings":          "csp_bypass",
    "open_redirect_findings":       "open_redirect",
}

# Regexy pro normalizaci payloadu/markeru → stabilní fingerprint.
# Markery scanneru jsou vysoko-entropní (XSGS..., xsg..., XSGSn...). Nahradíme
# je placeholderem, aby fingerprint nezávisel na konkrétní per-běh hodnotě.
_MARKER_RE = re.compile(r"(?i)\b(?:xsgs?n?|xsg)[a-z0-9_\-]{4,}\b")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{8,}\b")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_for_fingerprint(value: Any) -> str:
    """Odstraní per-běh entropii (markery, dlouhá hex/čísla) z textu."""
    if value is None:
        return ""
    s = str(value)
    s = _MARKER_RE.sub("<MARKER>", s)
    s = _HEX_RE.sub("<HEX>", s)
    return s.strip()


def _strip_url_dynamic(url: str) -> str:
    """Vrátí scheme+host+path + setříděná JMÉNA parametrů (bez hodnot).

    Hodnoty parametrů obsahují injektovaný payload/marker → nestabilní.
    Jména parametrů ano (identita endpointu).
    """
    if not url:
        return ""
    try:
        from urllib.parse import urlsplit, parse_qsl
        sp = urlsplit(url)
        base = f"{sp.scheme}://{sp.netloc}{sp.path}"
        names = sorted({k for k, _ in parse_qsl(sp.query, keep_blank_values=True)})
        if names:
            base += "?" + "&".join(names)
        return base
    except Exception:
        return _normalize_for_fingerprint(url)


def _first(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


class FindingStore:
    """Append-only JSONL store pro nálezy + jejich evidenci.

    Použití:
        store = FindingStore(path, scanner_version="v10.23",
                             origin="public", retention_days=None,
                             target="http://...")
        store.ingest_report(report_dict)   # uloží VŠECHNY kategorie
        store.close()
    """

    def __init__(self,
                 path: str,
                 scanner_version: str = "unknown",
                 origin: str = "public",
                 retention_days: Optional[int] = None,
                 target: Optional[str] = None,
                 scan_id: Optional[str] = None) -> None:
        self.path = path
        self.scanner_version = scanner_version
        self.origin = origin if origin in ("public", "consented", "client") else "public"
        self.retention_days = retention_days
        self.target = target or ""
        self.scan_id = scan_id or uuid.uuid4().hex
        self._lock = threading.Lock()
        self._seen_fp: set = set()   # dedup v rámci jednoho skenu (scan_id)
        self._count = 0
        # zajisti adresář
        d = os.path.dirname(os.path.abspath(path))
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)

    # ── fingerprint ──────────────────────────────────────────────────────
    def _fingerprint(self, finding: Dict[str, Any], kind: str) -> str:
        """Stabilní identita nálezu napříč běhy (nezávislá na markeru/času).

        Komponenty: kind + endpoint(URL bez hodnot) + param + kontext +
        umístění sinku (source/gadget file:line nebo cwe).

        POZN.: payload se ZÁMĚRNĚ NEzahrnuje. Scanner pro tutéž díru může
        napříč běhy reportovat různý payload podle toho, který se protlačil
        první (polyglot vs <svg> apod.) — payload je EVIDENCE, ne identita.
        Identita = injekční bod, ne konkrétní střela. Tohle odpovídá i dedup
        logice scanneru ("endpoint+param+kontext = 1 bug").
        """
        url = _first(finding, "url", "test_url", "view_url", "response_url",
                     "ws_url", default="")
        param = _first(finding, "param", "source_origin", default="")
        ctx = _first(finding, "context", "ti_context", default="")
        sink = "|".join(str(x) for x in (
            _first(finding, "source_file", "gadget_file", "file", default=""),
            _first(finding, "source_line", "gadget_line", "line", default=""),
            _first(finding, "source_pattern", "gadget_property", default=""),
            _first(finding, "cwe", "cwe_hint", default=""),
        ))
        basis = "\x1f".join([
            kind,
            _strip_url_dynamic(str(url)),
            _normalize_for_fingerprint(param),
            _normalize_for_fingerprint(ctx),
            _normalize_for_fingerprint(sink),
        ])
        return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:32]

    # ── evidence extrakce ────────────────────────────────────────────────
    @staticmethod
    def _reflection_fidelity(finding: Dict[str, Any]) -> str:
        """unique_nonce_echo | shape_match | none | unknown.

        Princip 'potvrzuje, nehádá': nález opřený o unikátní marker echo má
        vyšší fidelitu než match na tvaru payloadu (zdroj historických FP).
        """
        if finding.get("marker_found") is True or finding.get("marker"):
            return "unique_nonce_echo"
        if finding.get("verification_required") is True:
            return "shape_match"   # odesláno, echo nepotvrzeno tímto endpointem
        if finding.get("dom_verified") is True:
            return "unique_nonce_echo"
        return "unknown"

    @staticmethod
    def _dynamic_confirmation(finding: Dict[str, Any]) -> str:
        if finding.get("dom_verified") is True:
            return "playwright_confirmed"
        if finding.get("verification_required") is True:
            return "pending_not_run"
        return "none"

    @staticmethod
    def _def_use(finding: Dict[str, Any]) -> Optional[bool]:
        # PP: ko-lokace bez ověřené def-use hrany se značí v popisu / orig sev.
        desc = str(_first(finding, "description", "evidence", "note", default="")).lower()
        if "def-use" in desc or "def use" in desc:
            return "without" not in desc and "bez" not in desc
        if "co-located" in desc or "ko-lokac" in desc or "ko-lokovan" in desc:
            return False
        return None

    @staticmethod
    def _param_origin(finding: Dict[str, Any]) -> str:
        ao = _first(finding, "source_origin", "arg_origin", "param_origin", default=None)
        if ao:
            return str(ao)
        # heuristika: pokud je marker_param / user-controlled param přítomen
        if finding.get("param"):
            return "user_controlled"
        return "unknown"

    def _extract_evidence(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "reflection_fidelity":   self._reflection_fidelity(finding),
            "executability_verdict": _first(finding, "dom_verified", "executable",
                                            default=None),
            "dynamic_confirmation":  self._dynamic_confirmation(finding),
            "context_class":         _first(finding, "context", "ti_context", default=None),
            "def_use_verified":      self._def_use(finding),
            # v10.24: FP-risk signál — klíčové pro ML (poctivý label: kandidát
            # vs potvrzený TP) i pro triage. Ko-lokační/shape-match nálezy bez
            # ověřeného flow nesou fp_risk=True + důvod + potential_severity.
            "fp_risk":               finding.get("fp_risk"),
            "fp_reason":             _first(finding, "fp_reason", "downgrade_reason",
                                            default=None),
            "potential_severity":    _first(finding, "potential_severity",
                                            "original_severity", default=None),
            "chain_verified":        finding.get("chain_verified"),
            "static_signal":         finding.get("static_signal"),
            # v10.24: detekční základ verze (filename vs content) — confidence
            # signál pro library nálezy. NENÍ to fp_risk (filename ~ obsah ve
            # většině případů), ale ML/triage to má vidět.
            "version_source":        finding.get("version_source"),
            "sanitizer":             _first(finding, "sanitizer", "sanitizer_info", default=None),
            "cve_match":             _first(finding, "cve", "cve_id", "patterns_matched",
                                            "matched_cves", default=None),
            "csp_state":             _first(finding, "csp_state", "csp", default=None),
            "verification_required": finding.get("verification_required"),
            "payload":               _first(finding, "payload", default=None),
            "evidence_snippet":      _first(finding, "evidence", "evidence_snippet",
                                            "error_pattern", default=None),
            "confidence":            _first(finding, "confidence", "ti_confidence",
                                            default=None),
            "marker":                _first(finding, "marker", default=None),
            # VŠECHNO ostatní verbatim — nic neztratit (širší záznam > úzký)
            "raw_finding":           finding,
        }

    # ── normalizace jednoho nálezu na záznam ─────────────────────────────
    def _build_record(self, finding: Dict[str, Any], category: str) -> Optional[Dict[str, Any]]:
        if not isinstance(finding, dict):
            # některé kategorie mohou nést dataclass.to_dict; zkus konverzi
            try:
                finding = dict(finding)
            except Exception:
                return None
        # v10.24 defenzivní pojistka: některé fáze emitují nález s detailem
        # vnořeným v sub-dictu (např. proto_pollution_finding) a nehoistnou
        # fp_risk/severity na top-level. Aby se fp_risk NIKDY neztratil (jinak
        # by ko-lokační kandidát šel do ML dat bez FP labelu), vnořené *_finding
        # detail dicty splošťujeme jako fallback (top-level klíče VYHRÁVAJÍ).
        # Pracujeme na KOPII — originál v report_dictu nesmíme mutovat.
        finding = dict(finding)
        for _k, _v in list(finding.items()):
            if _k.endswith("_finding") and isinstance(_v, dict):
                for _dk, _dv in _v.items():
                    finding.setdefault(_dk, _dv)
        kind = _CATEGORY_MAP.get(category, category)
        fp = self._fingerprint(finding, kind)
        severity = str(_first(finding, "severity", default="info")).lower()
        # normalizace severity na kanonickou škálu
        sev_map = {"informational": "info", "informative": "info", "none": "info",
                   "low": "low", "medium": "medium", "moderate": "medium",
                   "high": "high", "critical": "critical"}
        severity = sev_map.get(severity, severity if severity in
                               ("info", "low", "medium", "high", "critical") else "info")
        url = _first(finding, "url", "test_url", "view_url", "response_url",
                     "ws_url", default="")
        host = ""
        try:
            from urllib.parse import urlsplit
            host = urlsplit(str(url)).netloc
        except Exception:
            pass

        expires_at = None
        if self.retention_days is not None:
            expires_at = (datetime.now(timezone.utc).timestamp()
                          + self.retention_days * 86400)
            expires_at = datetime.fromtimestamp(expires_at, timezone.utc).isoformat()

        # v10.28: advisory skóre z promote-vrstvy — transparentní confidence +
        # doporučená severita + interpretovatelné důvody, persistované u
        # každého nálezu (pro triage ranking i pozdější ML). Lazy import kvůli
        # cyklu; selhání scoreru nesmí shodit ukládání.
        score_block = None
        try:
            from _finding_scorer import score_finding as _score_finding
            score_block = _score_finding(finding).to_dict()
        except Exception:
            score_block = None

        return {
            "schema_version":   SCHEMA_VERSION,
            "record_id":        uuid.uuid4().hex,
            "fingerprint":      fp,
            "scan_id":          self.scan_id,
            "timestamp":        _utc_now_iso(),

            # provenance / verzování
            "scanner_version":  self.scanner_version,
            "detector":         category,
            "detector_kind":    kind,

            # cíl
            "target": {
                "scan_target": self.target,
                "url":         str(url),
                "host":        host,
                "param":       _first(finding, "param", default=None),
                "method":      _first(finding, "method", default=None),
                "param_origin": self._param_origin(finding),
            },

            # VERDIKT (výstup heuristiky — oddělený od evidence)
            "verdict": {
                "severity":   severity,
                "kind":       kind,
                "context":    _first(finding, "context", "ti_context", default=None),
                "cwe":        _first(finding, "cwe", "cwe_hint", default=None),
                "source":     _first(finding, "source", default=None),
                # FP-risk je součást verdiktu: nález s fp_risk=True NENÍ
                # potvrzený TP — pro ML je to label "kandidát", ne "exploit".
                "fp_risk":            finding.get("fp_risk", False),
                "potential_severity": _first(finding, "potential_severity",
                                             "original_severity", default=None),
            },

            # EVIDENCE (vstupní featury pro ML + raw)
            "evidence": self._extract_evidence(finding),

            # ADVISORY SCORE (v10.28 promote-vrstva) — transparentní, NEpřebíjí
            # detektor; recommended_severity respektuje fp_risk gate, score řadí
            # neověřené kandidáty pro triage.
            "score": score_block,

            # GROUND-TRUTH label (zatím prázdný — plní triage / bug bounty)
            "label": {
                "ground_truth": None,   # confirmed|dismissed|duplicate|exploited
                "labeled_by":   None,
                "labeled_at":   None,
                "notes":        None,
            },

            # DATA GOVERNANCE
            "origin": self.origin,
            "retention": {
                "policy":               (f"{self.retention_days}d"
                                         if self.retention_days else "indefinite"),
                "expires_at":           expires_at,
                "contains_client_data": self.origin in ("consented", "client"),
            },
        }

    # ── zápis ────────────────────────────────────────────────────────────
    def record(self, finding: Dict[str, Any], category: str) -> bool:
        rec = self._build_record(finding, category)
        if rec is None:
            return False
        with self._lock:
            if rec["fingerprint"] in self._seen_fp:
                return False   # dedup v rámci skenu
            self._seen_fp.add(rec["fingerprint"])
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
            self._count += 1
        return True

    def ingest_report(self, report_dict: Dict[str, Any]) -> int:
        """Uloží VŠECHNY nálezy ze všech kategorií report_dictu.

        Vrací počet zapsaných (po dedup v rámci skenu) záznamů.
        """
        written = 0
        for key, value in report_dict.items():
            if key in _NON_FINDING_KEYS:
                continue
            if not isinstance(value, list):
                continue
            for item in value:
                # v10.77: avoid double-recording. An emitted hit in "findings"
                # that carries a *_finding sub-dict (dom_v6/stored/PP/mXSS/
                # static-JS/DC/SSR/…) is the SAME underlying finding as the item
                # in its typed list, but the fingerprint includes the category-
                # derived `kind`, so the two representations got DIFFERENT
                # fingerprints and BOTH were written. Record such findings once,
                # via their typed list; "findings" entries WITHOUT a *_finding
                # sub-dict (classic reflection, CORS, XSSI, …) are still recorded.
                if key == "findings" and isinstance(item, dict) and any(
                        k.endswith("_finding") and isinstance(item.get(k), dict)
                        for k in item):
                    continue
                if self.record(item, key):
                    written += 1
        return written

    @property
    def count(self) -> int:
        return self._count

    def close(self) -> None:
        # JSONL nepotřebuje explicitní close, ponecháno pro symetrii / future.
        pass


# ── helper pro analýzu uloženého storu (drift / labeling pipeline) ────────
def load_records(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


# ── TRIAGE / GROUND-TRUTH (v10.28) ────────────────────────────────────────
# Bez ground-truth labelů (confirm/dismiss) není z čeho učit ML. Labely se
# zapisují APPEND-ONLY do sidecar souboru "<store>.labels.jsonl" — findings
# store zůstává immutable, vzniká audit trail label eventů (last-write-wins
# per fingerprint). label.ground_truth ve findings záznamu je placeholder;
# autoritativní je sidecar.

_VALID_LABELS = {"confirmed", "dismissed", "duplicate", "exploited", "unsure"}
# mapování na binární cíl pro ML (None = vynechat z tréninku)
_LABEL_TO_BINARY = {
    "confirmed": 1, "exploited": 1,
    "dismissed": 0,
    "duplicate": None, "unsure": None,
}


def _labels_path(store_path: str) -> str:
    return store_path + ".labels.jsonl"


def record_label(store_path: str, fingerprint: str, ground_truth: str,
                 labeled_by: Optional[str] = None,
                 notes: Optional[str] = None) -> bool:
    """Zapíše triage rozhodnutí (append-only). ground_truth ∈ _VALID_LABELS."""
    gt = str(ground_truth).lower().strip()
    if gt not in _VALID_LABELS:
        raise ValueError(f"ground_truth musí být jeden z {sorted(_VALID_LABELS)}, "
                         f"dostal jsem {ground_truth!r}")
    if not fingerprint:
        raise ValueError("fingerprint je povinný")
    event = {
        "fingerprint": fingerprint,
        "ground_truth": gt,
        "labeled_by": labeled_by,
        "labeled_at": _utc_now_iso(),
        "notes": notes,
    }
    lp = _labels_path(store_path)
    d = os.path.dirname(os.path.abspath(lp))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    with open(lp, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
    return True


def load_labels(store_path: str) -> Dict[str, Dict[str, Any]]:
    """Vrátí {fingerprint: poslední label event} (last-write-wins)."""
    out: Dict[str, Dict[str, Any]] = {}
    lp = _labels_path(store_path)
    if not os.path.isfile(lp):
        return out
    with open(lp, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            fp = ev.get("fingerprint")
            if fp:
                out[fp] = ev   # pozdější přepíše dřívější
    return out


def prepare_training_data(store_path: str) -> List[Dict[str, Any]]:
    """Spojí findings + labely → trénovací příklady (features, label).

    Vrací jen záznamy, které MAJÍ binární label (confirmed/exploited=1,
    dismissed=0). duplicate/unsure se vynechají. Tohle je vstup pro pozdější
    interpretovatelný learned ranker (logistic regression / GBT+SHAP).
    """
    try:
        from _finding_scorer import extract_features as _extract
    except Exception:
        _extract = None
    records = load_records(store_path)
    labels = load_labels(store_path)
    examples: List[Dict[str, Any]] = []
    seen_fp: set = set()
    for rec in records:
        fp = rec.get("fingerprint")
        if not fp or fp in seen_fp or fp not in labels:
            continue
        gt = labels[fp].get("ground_truth")
        binary = _LABEL_TO_BINARY.get(gt)
        if binary is None:
            continue
        seen_fp.add(fp)
        feats = _extract(rec) if _extract else {}
        examples.append({
            "fingerprint": fp,
            "features": feats,
            "label": binary,
            "ground_truth": gt,
            "detector": rec.get("detector"),
        })
    return examples


def labeling_stats(store_path: str) -> Dict[str, Any]:
    """Přehled stavu labelování — kolik nálezů má/nemá ground-truth (pro
    rozhodnutí, kdy je dost dat na trénink)."""
    records = load_records(store_path)
    labels = load_labels(store_path)
    fps = {r.get("fingerprint") for r in records if r.get("fingerprint")}
    by_gt: Dict[str, int] = {}
    for fp in fps:
        gt = labels.get(fp, {}).get("ground_truth", "unlabeled")
        by_gt[gt] = by_gt.get(gt, 0) + 1
    trainable = sum(1 for fp in fps
                    if _LABEL_TO_BINARY.get(labels.get(fp, {}).get("ground_truth")) is not None)
    return {
        "unique_findings": len(fps),
        "labeled": sum(1 for fp in fps if fp in labels),
        "trainable_examples": trainable,
        "by_ground_truth": by_gt,
    }
