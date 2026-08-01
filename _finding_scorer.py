"""
_finding_scorer.py — Vážicí/promote vrstva nad evidence (v10.28).

ROLE (dle dohody s TX-C0RE — třístupňový model):
    detekce na INFO floor (vše viditelné) → TADY vážení/promote (eskaluje jen
    to, co má váhu) → high/critical jen PROVEN (fp_risk=False).

PROČ DETERMINISTICKY NEJDŘÍV (a ne rovnou ML):
    ML je downstream od OLABELOVANÝCH dat. Bez ground-truth (triage confirm/
    dismiss) není z čeho trénovat. Tahle vrstva:
      1) dává JEDNOTNÝ, TRANSPARENTNÍ rubrik napříč detektory (ne ad-hoc
         severity v každém),
      2) produkuje INTERPRETOVATELNÉ důvody (která featura kolik přispěla —
         SHAP-like, ale deterministicky),
      3) je ML-READY: extract_features() vrací plochý číselný vektor, který
         později nakrmí learned ranker (score_finding má hák load_model()).

    Dokud nejsou labely, score_finding() jede deterministický rubrik. Až
    triage nasbírá ground-truth, prepare_training_data() (v _finding_store)
    dá (features, label) páry a sem se připojí kalibrovaný interpretovatelný
    model (logistic regression / GBT+SHAP) — NE black-box.

KLÍČOVÉ PRAVIDLO: žádný high/critical bez důkazu. Když je fp_risk=True
(detektor sám nedokázal ověřit flow), strop je low — ale signál se NEzahazuje
(zůstává viditelný + olabelovaný jako kandidát).

Stdlib-only.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

SCORER_VERSION = "rubric-1.0"

# Kanonická škála
_SEV_ORDER = ["info", "low", "medium", "high", "critical"]
_SEV_RANK = {s: i for i, s in enumerate(_SEV_ORDER)}


# ── Transparentní váhy (laditelné, dokumentované) ────────────────────────
# Každý příspěvek je v "log-odds"-like prostoru; sečtou se a zmáčknou do [0,1].
# Kladné = víc důvěry, že je to PRAVÝ exploitovatelný nález; záporné = míň.
FEATURE_WEIGHTS: Dict[str, Dict[Any, float]] = {
    # Runtime potvrzení = nejsilnější důkaz (proto je to brána pro high/crit).
    "dynamic_confirmation": {
        "playwright_confirmed": +0.50,
        "pending_not_run":      0.0,
        "none":                 0.0,
    },
    # Unikátní marker echo > shape-match (shape-match byl zdroj historických FP).
    "reflection_fidelity": {
        "unique_nonce_echo": +0.20,
        "shape_match":       +0.05,
        "none":              0.0,
        "unknown":           0.0,
    },
    # Spustitelnost kontextu.
    "executability_verdict": {True: +0.15, False: -0.10, None: 0.0},
    # Ověřená def-use hrana (PP chain): True silně kladné, ko-lokace záporné.
    "def_use_verified":      {True: +0.20, False: -0.15, None: 0.0},
    # Síla statického signálu.
    "static_signal":         {"strong": +0.08, "weak": 0.0, None: 0.0},
    # Detektor sám flagnul nejistotu → dolů (a později brána).
    "fp_risk":               {True: -0.20, False: +0.05, None: 0.0},
    # Čeká na ověření.
    "verification_required": {True: -0.10, False: 0.0, None: 0.0},
    # Verze knihovny z názvu souboru < z obsahu.
    "version_source":        {"filename": -0.05, "source": +0.05, None: 0.0},
}

# Kontext: spustitelné vs inertní (textarea/komentář/encoded).
_EXECUTABLE_CONTEXTS = (
    "html_body", "script_body", "js", "html-body", "script-body",
    "html_attr", "attr_breakout", "uri_attr", "event_handler",
)
_INERT_CONTEXTS = (
    "textarea", "comment", "html-comment", "encoded", "inert", "rcdata",
    "noscript", "plaintext",
)
_CONTEXT_W_EXEC = +0.10
_CONTEXT_W_INERT = -0.20

# CVE signatura přítomná (jen mírně — sama o sobě bez reachability není důkaz).
_CVE_PRESENT_W = +0.08


def _sigmoid(x: float) -> float:
    import math
    try:
        return 1.0 / (1.0 + math.exp(-x))
    except OverflowError:
        return 0.0 if x < 0 else 1.0


def _get(f: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Hledá klíč na top-level i ve vnořené evidence/raw_finding."""
    for k in keys:
        if k in f and f[k] is not None:
            return f[k]
    ev = f.get("evidence")
    if isinstance(ev, dict):
        for k in keys:
            if k in ev and ev[k] is not None:
                return ev[k]
    vd = f.get("verdict")
    if isinstance(vd, dict):
        for k in keys:
            if k in vd and vd[k] is not None:
                return vd[k]
    return default


def _norm_context(ctx: Any) -> str:
    s = str(ctx or "").lower()
    # ořízni "(...)" sufixy typu "proto-pollution-chain (info)"
    s = s.split("(")[0].strip()
    return s


def extract_features(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Plochý feature dict — vstup pro rubrik I pozdější learned model.

    Funguje jak na syrovém finding dictu, tak na store záznamu (hledá v
    evidence/verdict).
    """
    ctx = _norm_context(_get(finding, "context", "context_class", "ti_context"))
    ctx_class = ("executable" if any(e in ctx for e in _EXECUTABLE_CONTEXTS)
                 else "inert" if any(i in ctx for i in _INERT_CONTEXTS)
                 else "unknown")
    return {
        "dynamic_confirmation": _get(finding, "dynamic_confirmation", default="none"),
        "reflection_fidelity":  _get(finding, "reflection_fidelity", default="unknown"),
        "executability_verdict": _get(finding, "executability_verdict", "dom_verified",
                                      default=None),
        "def_use_verified":     _get(finding, "def_use_verified", default=None),
        "static_signal":        _get(finding, "static_signal", default=None),
        "fp_risk":              _get(finding, "fp_risk", default=None),
        "verification_required": _get(finding, "verification_required", default=None),
        "version_source":       _get(finding, "version_source", default=None),
        "context_class":        ctx_class,
        "cve_present":          bool(_get(finding, "cve_match", "cve", "cve_id",
                                          default=None)),
        "detector_severity":    str(_get(finding, "severity", default="info")).lower(),
        "potential_severity":   _get(finding, "potential_severity",
                                     "original_severity", default=None),
    }


class ScoreResult:
    """Výsledek skórování — transparentní a serializovatelný."""
    __slots__ = ("score", "recommended_severity", "fp_risk", "gate_applied",
                 "reasons", "scorer_version")

    def __init__(self, score, recommended_severity, fp_risk, gate_applied,
                 reasons, scorer_version=SCORER_VERSION):
        self.score = score
        self.recommended_severity = recommended_severity
        self.fp_risk = fp_risk
        self.gate_applied = gate_applied
        self.reasons = reasons
        self.scorer_version = scorer_version

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "recommended_severity": self.recommended_severity,
            "fp_risk": self.fp_risk,
            "gate_applied": self.gate_applied,
            "reasons": self.reasons,
            "scorer_version": self.scorer_version,
        }


def _ceiling(detector_sev: str, potential_sev: Optional[str]) -> str:
    """Strop, který scorer nepřekročí — nevymýšlíme vyšší závažnost, než dává
    detektor (resp. jeho potential)."""
    cap = detector_sev if detector_sev in _SEV_RANK else "info"
    if potential_sev and potential_sev in _SEV_RANK:
        if _SEV_RANK[potential_sev] > _SEV_RANK[cap]:
            cap = potential_sev
    return cap


def score_finding(finding: Dict[str, Any],
                  model: Optional[Any] = None) -> ScoreResult:
    """Deterministický (nebo learned, je-li model) skór + doporučená severita.

    HARD GATES (přebíjejí skóre):
      - high/critical JEN když fp_risk != True (důkaz, ne ko-lokace).
      - inertní kontext nikdy nepromuje nad low.
    """
    feats = extract_features(finding)

    # ── learned model hook (až budou data) ──
    if model is not None:
        try:
            p = float(model.predict_proba_one(feats))  # očekává [0,1]
            return _result_from_score(p, feats,
                                      reasons=[{"feature": "learned_model",
                                                "contribution": round(p, 4)}],
                                      scorer_version=getattr(model, "version",
                                                             "learned"))
        except Exception:
            pass  # fallback na deterministický rubrik

    # ── deterministický rubrik ──
    contributions: List[Tuple[str, Any, float]] = []

    def add(feature_name: str, value: Any, w: float):
        if w != 0.0:
            contributions.append((feature_name, value, w))

    for fname, table in FEATURE_WEIGHTS.items():
        val = feats.get(fname)
        if val in table:
            add(fname, val, table[val])

    # kontext
    cc = feats.get("context_class")
    if cc == "executable":
        add("context_class", cc, _CONTEXT_W_EXEC)
    elif cc == "inert":
        add("context_class", cc, _CONTEXT_W_INERT)

    # CVE přítomnost
    if feats.get("cve_present"):
        add("cve_present", True, _CVE_PRESENT_W)

    raw = sum(w for _, _, w in contributions)
    score = _sigmoid(raw * 3.0)  # škálování pro rozumný spread kolem 0.5

    res = _result_from_score(score, feats, reasons=[
        {"feature": n, "value": v, "contribution": round(w, 4)}
        for (n, v, w) in sorted(contributions, key=lambda c: -abs(c[2]))
    ])
    return res


def _result_from_score(score: float, feats: Dict[str, Any],
                       reasons: List[Dict[str, Any]],
                       scorer_version: str = SCORER_VERSION) -> ScoreResult:
    detector_sev = str(feats.get("detector_severity") or "info")
    detector_sev = detector_sev if detector_sev in _SEV_RANK else "info"
    detector_fp_risk = feats.get("fp_risk") is True
    ceiling = _ceiling(detector_sev, feats.get("potential_severity"))

    # rubrikový tier ze skóre (čistě z evidence)
    if score >= 0.75:
        rubric_tier = "high"
    elif score >= 0.55:
        rubric_tier = "medium"
    elif score >= 0.35:
        rubric_tier = "low"
    else:
        rubric_tier = "info"

    gate = None
    # ── KLÍČOVÉ: scorer je ADVISORY a NEPŘEBÍJÍ detektorovo gating ──
    # Detektory už mají pečlivě laděné fp_risk brány (v10.24–25). Scorer je
    # nesmí srazit — jinak by zničil recall (např. CORS+credentials je z
    # ODPOVĚDI prokázaný critical, ale nemá browser-confirmation featuru).
    if detector_fp_risk:
        # NEOVĚŘENÝ kandidát: strop low (žádný promote bez důkazu). Skóre tady
        # slouží jako PRIORITA pro triage (které kandidáty řešit první).
        if _SEV_RANK.get(rubric_tier, 0) > _SEV_RANK["low"]:
            recommended = "low"
            gate = ("fp_risk: unverified → capped at low (no promote without "
                    "proof); score = triage priority among candidates")
        else:
            recommended = rubric_tier
        rec_fp_risk = True
    else:
        # Detektor nález PROKÁZAL (fp_risk=False) → respektuj jeho severitu.
        # Scorer ji NEsnižuje; skóre je advisory confidence.
        recommended = detector_sev
        rec_fp_risk = False

    # Inert-context capping is ALREADY enforced by the fp_risk/proven split
    # above: an unverified finding (fp_risk=True) is capped to low regardless of
    # context, and a detector-PROVEN finding (fp_risk=False) is respected — which
    # is exactly the documented "cap inert unless the detector proved higher"
    # policy. v10.80: removed a dead guard here that compared `recommended`
    # (already == detector_sev in the proven branch), making its two rank
    # conditions mutually exclusive so it never fired; leaving it implied an
    # active gate that did nothing. `context_class` is retained for the
    # feature/telemetry record, not a second cap.

    # nikdy nad ceiling
    if _SEV_RANK.get(recommended, 0) > _SEV_RANK.get(ceiling, 4):
        recommended = ceiling

    # ── DISAGREEMENT flag: skóre vs detektor silně diverguje → k revizi ──
    disagreement = None
    drank = _SEV_RANK.get(detector_sev, 0)
    if score >= 0.78 and drank <= _SEV_RANK["low"] and not detector_fp_risk:
        disagreement = ("score HIGH but detector severity low — finding may be "
                        "under-rated; review")
    elif score <= 0.25 and drank >= _SEV_RANK["high"]:
        disagreement = ("score LOW but detector severity high — possible "
                        "over-rating; review")
    if disagreement:
        gate = (gate + " | " if gate else "") + disagreement

    return ScoreResult(
        score=score,
        recommended_severity=recommended,
        fp_risk=rec_fp_risk,
        gate_applied=gate,
        reasons=reasons,
        scorer_version=scorer_version,
    )


def annotate_finding(finding: Dict[str, Any],
                     model: Optional[Any] = None) -> Dict[str, Any]:
    """Vrátí KOPII findingu s přidaným 'score' blokem (advisory — nemění
    detektorovu severity, jen doplní transparentní doporučení)."""
    res = score_finding(finding, model=model)
    out = dict(finding)
    out["score"] = res.to_dict()
    return out
