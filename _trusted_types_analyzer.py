"""
_trusted_types_analyzer.py
==========================
Trusted Types policy analyzer — detects insecure CSP Trusted Types config.

Background
----------
Trusted Types (Chromium 83+; other engines have lagged — do not assume it is
active outside Chromium) is a strong defense against DOM XSS. Apps opt in via CSP:

    Content-Security-Policy: require-trusted-types-for 'script';
                             trusted-types myPolicy

Once enforced, all sinks (innerHTML, eval, ...) require a TrustedHTML/Script
object created via a registered policy. This eliminates entire class of
"forgotten sanitization" bugs.

BUT: developers often misconfigure it. Common mistakes:
  1. `default` policy with pass-through createHTML — silently allows ALL
     string assignments to bypass TT. This is a SILENT BACKDOOR.
  2. Permissive createHTML that returns input as-is or with weak filtering
     (regex strip <script>, etc.) instead of using DOMPurify.
  3. report-only mode (Content-Security-Policy-Report-Only) treated as
     enforcement — violations are logged but not blocked.
  4. `trusted-types *` wildcard — any script can create a policy named
     anything, including 'default'.

Detection
---------
Phase 1: CSP header parsing
  - Look for `require-trusted-types-for 'script'` (enforcement directive)
  - Parse `trusted-types <names>` directive (allowed policy names)
  - Detect `*` wildcard, `'allow-duplicates'`, missing enforcement, etc.

Phase 2: JS source audit (when TT is in CSP)
  - Find `trustedTypes.createPolicy(name, {createHTML, createScript, ...})`
    calls in inline scripts and external JS.
  - Audit each policy's transformer functions:
    - Pass-through: `(input) => input` → BACKDOOR
    - Identity-style: function returns its argument unchanged
    - Weak: simple regex (e.g. `.replace(/<script.*?>/g, '')`)
    - Safe: calls DOMPurify, sanitizer, validates input
  - Highlight `default` policy as critical (implicit conversion sink).

Phase 3: Cross-reference
  - If static_js found innerHTML/eval sinks AND CSP has TT enforcement
    AND policy is insecure → CONFIRMED bypass

Public API
----------

    analyze_csp_header(csp_value: str) -> CSPTrustedTypesInfo
        Parse CSP header, return TT-related findings.

    audit_policy_definitions(js_source: str) -> List[TTPolicyFinding]
        Find createPolicy() calls and audit each policy function.

    TrustedTypesReport
        Combined view: header + policy audits + recommendation.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("xss_grenade.trusted_types")

try:
    import esprima
    _ESPRIMA_AVAILABLE = True
except ImportError:
    _ESPRIMA_AVAILABLE = False
    esprima = None


# ──────────────────────────────────────────────────────────────────────────────
# DATA TYPES
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class CSPTrustedTypesInfo:
    """Result of parsing CSP header for Trusted Types directives."""
    raw_csp: str = ""
    enforced: bool = False           # require-trusted-types-for 'script' present
    report_only: bool = False        # came from CSP-Report-Only header
    allowed_policies: List[str] = field(default_factory=list)
    wildcard: bool = False           # `trusted-types *` present
    allow_duplicates: bool = False   # 'allow-duplicates' keyword
    has_default_in_allowlist: bool = False
    issues: List[str] = field(default_factory=list)
    severity: str = "info"           # info / low / medium / high

    @property
    def opted_in(self) -> bool:
        """True if app uses Trusted Types in any form."""
        return self.enforced or bool(self.allowed_policies) or self.wildcard


@dataclass
class TTPolicyFinding:
    """Audit result for one createPolicy() call."""
    policy_name: str
    file: str
    line: int
    methods_defined: List[str] = field(default_factory=list)
    insecure_methods: List[Tuple[str, str]] = field(default_factory=list)
    # ↑ list of (method_name, reason) — e.g. ("createHTML", "pass-through")
    is_default_policy: bool = False
    severity: str = "info"
    snippet: str = ""

    @property
    def insecure(self) -> bool:
        return len(self.insecure_methods) > 0


@dataclass
class TrustedTypesReport:
    """Combined Trusted Types analysis for one URL/page."""
    url: str = ""
    csp_info: Optional[CSPTrustedTypesInfo] = None
    policy_findings: List[TTPolicyFinding] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        if self.csp_info and self.csp_info.issues:
            return True
        return any(p.insecure for p in self.policy_findings)


# ──────────────────────────────────────────────────────────────────────────────
# CSP PARSING
# ──────────────────────────────────────────────────────────────────────────────

def analyze_csp_header(csp_value: str,
                        report_only: bool = False) -> CSPTrustedTypesInfo:
    """Parse a CSP header and extract Trusted Types information.

    Args:
        csp_value: raw CSP header value (everything after `Content-Security-Policy:`)
        report_only: True if header was Content-Security-Policy-Report-Only

    Returns CSPTrustedTypesInfo with detected configuration + issues.
    """
    info = CSPTrustedTypesInfo(raw_csp=csp_value or "", report_only=report_only)
    if not csp_value:
        return info

    # CSP is `directive value; directive value; ...`
    directives: Dict[str, List[str]] = {}
    for chunk in csp_value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split()
        if not parts:
            continue
        name = parts[0].lower()
        directives[name] = parts[1:]

    # Enforcement directive: require-trusted-types-for 'script'
    rttf = directives.get("require-trusted-types-for", [])
    # Values are quoted: 'script'
    if any(v.strip("'\"") == "script" for v in rttf):
        info.enforced = True

    # trusted-types directive: lists allowed policy names + special keywords
    tt = directives.get("trusted-types", None)
    if tt is not None:
        for token in tt:
            tok = token.strip("'\"")
            if tok == "*":
                info.wildcard = True
            elif tok == "allow-duplicates":
                info.allow_duplicates = True
            elif tok == "none":
                # 'none' means no policies allowed — strict
                pass
            else:
                info.allowed_policies.append(tok)
                if tok == "default":
                    info.has_default_in_allowlist = True

    # ── Issue detection ────────────────────────────────────────────────
    if not info.opted_in:
        info.issues.append("Žádný Trusted Types config v CSP — DOM XSS sinky nejsou chráněné")
        info.severity = "info"   # informační — ne každá app by měla TT
    else:
        if info.report_only:
            info.issues.append(
                "Trusted Types jen v Report-Only módu — porušení se logují, "
                "ale neblokují. Útočník není zastavený."
            )
            info.severity = "high"
        if not info.enforced and info.allowed_policies:
            info.issues.append(
                "trusted-types directive nastaven, ale chybí "
                "require-trusted-types-for 'script' — TT se nevynucuje pro JS sinky"
            )
            info.severity = "medium"
        if info.wildcard:
            info.issues.append(
                "trusted-types * (wildcard) — jakýkoliv script může vytvořit policy "
                "s libovolným názvem včetně 'default'. Defeats whole purpose."
            )
            info.severity = "high"
        if info.has_default_in_allowlist:
            info.issues.append(
                "'default' policy je v allowlistu — pokud je její createHTML "
                "permisivní, všechny string-to-sink konverze projdou bez TrustedHTML wrap. "
                "Audituj definici default policy v JS."
            )
            if info.severity not in ("high",):
                info.severity = "medium"

    return info


# ──────────────────────────────────────────────────────────────────────────────
# JS POLICY AUDIT (AST-based)
# ──────────────────────────────────────────────────────────────────────────────

def _node_type(node) -> str:
    return getattr(node, "type", "") or ""


def _get_loc_line(node) -> int:
    try:
        return node.loc.start.line
    except (AttributeError, TypeError):
        return 0


def _walk(node, callback, depth: int = 0, max_depth: int = 200):
    if depth > max_depth:
        return
    if not hasattr(node, "type"):
        return
    callback(node)
    SKIP = {
        "type", "loc", "range", "name", "value", "raw", "kind",
        "operator", "regex", "computed", "shorthand", "method",
        "prefix", "delegate", "async", "generator", "static",
        "directive",
    }
    for attr in dir(node):
        if attr.startswith("_") or attr in SKIP:
            continue
        try:
            v = getattr(node, attr)
        except Exception:
            continue
        if isinstance(v, list):
            for item in v:
                _walk(item, callback, depth + 1, max_depth)
        elif hasattr(v, "type"):
            _walk(v, callback, depth + 1, max_depth)


# Patterns indicating the function body looks safe. IMPORTANT: require the
# safe lib to be INVOKED (a call — keyword optionally followed by member access
# then `(`), not merely MENTIONED. Matching a bare keyword anywhere in the body
# text let a backdoor be classified safe just by naming a lib in a comment or
# string, e.g. `createHTML: s => eval("/*DOMPurify*/" + s)` — a false negative.
_SAFE_LIB_PATTERNS = re.compile(
    r"\b(?:DOMPurify|sanitize|sanitizer|setHTML|sanitizeFor|"
    r"createHTMLDocument|createSanitizer|escape|encodeURI|encodeURIComponent|"
    r"Sanitizer|HTMLSanitizer)\b(?:\s*\.\s*\w+)*\s*\("
)
# Patterns that suggest weak/regex-based "sanitization" — better than nothing
# but typically bypassable.
_WEAK_PATTERNS = re.compile(
    r"\.replace\s*\(\s*/[^/]*<\s*script[^/]*/[gimsy]*\s*,|"
    r"\.replace\s*\(\s*['\"]<script['\"]\s*,"
)


def _classify_method_body(method_name: str, fn_node, source_text: str) -> Optional[str]:
    """Return reason string if method body is insecure, None if probably safe.

    Heuristics:
    - Empty/identity body returning the input → pass-through (BACKDOOR)
    - Body uses DOMPurify/sanitize/Sanitizer API → SAFE (return None)
    - Body only does regex .replace() on <script> → WEAK (bypassable)
    - Anything else → can't tell, mark as 'unverified' (low severity)
    """
    if fn_node is None:
        return "no body"

    # Extract body text from source if possible (for regex patterns)
    body_text = ""
    try:
        if hasattr(fn_node, "range") and fn_node.range:
            start, end = fn_node.range
            body_text = source_text[start:end]
    except Exception:
        body_text = ""

    # Determine if function is identity (returns its single argument unchanged)
    is_identity = False
    params = getattr(fn_node, "params", None) or []
    param_names = [
        p.name for p in params if _node_type(p) == "Identifier"
    ]
    body = getattr(fn_node, "body", None)

    # Arrow function with implicit return: (x) => x
    if (_node_type(fn_node) == "ArrowFunctionExpression"
            and body is not None
            and _node_type(body) == "Identifier"):
        if body.name in param_names:
            is_identity = True

    # Block body — check for `return <Identifier>` only
    if (body is not None
            and _node_type(body) == "BlockStatement"):
        statements = getattr(body, "body", None) or []
        # Filter out variable declarations and noise
        non_trivial = [s for s in statements
                       if _node_type(s) not in ("EmptyStatement",)]
        if len(non_trivial) == 1:
            stmt = non_trivial[0]
            if (_node_type(stmt) == "ReturnStatement"
                    and stmt.argument is not None
                    and _node_type(stmt.argument) == "Identifier"
                    and stmt.argument.name in param_names):
                is_identity = True

    if is_identity:
        return "pass-through (returns input unchanged — silent backdoor)"

    # Library check
    if body_text and _SAFE_LIB_PATTERNS.search(body_text):
        return None  # safe

    # Weak regex check
    if body_text and _WEAK_PATTERNS.search(body_text):
        return "weak regex sanitization (bypassable)"

    # If we got here, body has some logic but doesn't reference known-safe libs
    return "unverified (no DOMPurify/Sanitizer call detected)"


def audit_policy_definitions(source_code: str,
                              source_name: str = "<inline>") -> List[TTPolicyFinding]:
    """Scan JS source for `trustedTypes.createPolicy()` calls and audit each.

    Returns list of TTPolicyFinding, one per createPolicy call.
    """
    if not _ESPRIMA_AVAILABLE or not source_code or not source_code.strip():
        return []

    try:
        tree = esprima.parseScript(
            source_code,
            options={"loc": True, "range": True, "tolerant": True}
        )
    except Exception:
        try:
            tree = esprima.parseModule(
                source_code,
                options={"loc": True, "range": True, "tolerant": True}
            )
        except Exception:
            return []

    findings: List[TTPolicyFinding] = []

    def visit(node):
        if _node_type(node) != "CallExpression":
            return
        callee = node.callee
        if _node_type(callee) != "MemberExpression":
            return
        # Must be: <something>.createPolicy(...)
        prop = callee.property
        if not getattr(callee, "computed", False):
            if _node_type(prop) != "Identifier" or prop.name != "createPolicy":
                return
        else:
            return  # computed createPolicy access is exotic; skip

        # Receiver should be `trustedTypes` or `window.trustedTypes` etc.
        # We accept any receiver that contains "trustedTypes" identifier in
        # the chain — keeps detection robust against minification.
        recv = callee.object
        recv_chain = []
        cur = recv
        while cur is not None:
            t = _node_type(cur)
            if t == "Identifier":
                recv_chain.append(cur.name)
                break
            elif t == "MemberExpression":
                if _node_type(cur.property) == "Identifier":
                    recv_chain.append(cur.property.name)
                cur = cur.object
            else:
                break
        if not any(n == "trustedTypes" for n in recv_chain):
            return

        # createPolicy(name, configObject)
        args = node.arguments or []
        if len(args) < 2:
            return
        name_arg = args[0]
        cfg_arg = args[1]
        # Extract policy name (must be string literal)
        policy_name = "<dynamic>"
        if _node_type(name_arg) == "Literal":
            v = getattr(name_arg, "value", None)
            if isinstance(v, str):
                policy_name = v
        elif _node_type(name_arg) == "TemplateLiteral":
            quasis = getattr(name_arg, "quasis", None) or []
            if len(quasis) == 1 and not (getattr(name_arg, "expressions", None) or []):
                cooked = getattr(quasis[0].value, "cooked", "")
                policy_name = cooked or "<dynamic>"

        finding = TTPolicyFinding(
            policy_name=policy_name,
            file=source_name,
            line=_get_loc_line(node),
            is_default_policy=(policy_name == "default"),
        )
        # Snippet from source
        try:
            if hasattr(node, "range") and node.range:
                start, end = node.range
                finding.snippet = source_code[start:end][:200]
        except Exception:
            pass

        # Walk config object — find createHTML, createScript, createScriptURL
        if _node_type(cfg_arg) == "ObjectExpression":
            for prop_node in (getattr(cfg_arg, "properties", None) or []):
                if _node_type(prop_node) != "Property":
                    continue
                key = getattr(prop_node, "key", None)
                key_name = None
                if key is not None:
                    if _node_type(key) == "Identifier":
                        key_name = key.name
                    elif _node_type(key) == "Literal":
                        v = getattr(key, "value", None)
                        if isinstance(v, str):
                            key_name = v
                if key_name not in ("createHTML", "createScript",
                                     "createScriptURL"):
                    continue
                finding.methods_defined.append(key_name)
                fn = getattr(prop_node, "value", None)
                reason = _classify_method_body(key_name, fn, source_code)
                if reason is not None:
                    finding.insecure_methods.append((key_name, reason))

        # Severity logic
        if finding.is_default_policy and finding.insecure_methods:
            # Default policy + insecure = critical (silent backdoor)
            finding.severity = "critical"
        elif any("pass-through" in r for _, r in finding.insecure_methods):
            finding.severity = "high"
        elif finding.insecure_methods:
            finding.severity = "medium"
        else:
            finding.severity = "info"

        findings.append(finding)

    _walk(tree, visit)
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# COMBINED REPORT
# ──────────────────────────────────────────────────────────────────────────────

def build_report(url: str,
                  csp_header: Optional[str] = None,
                  csp_report_only: Optional[str] = None,
                  inline_scripts: Optional[List[str]] = None,
                  external_scripts: Optional[Dict[str, str]] = None
                  ) -> TrustedTypesReport:
    """One-shot analysis: parse CSP + audit all script sources.

    Args:
        url: target URL (for report attribution)
        csp_header: value of Content-Security-Policy header (optional)
        csp_report_only: value of Content-Security-Policy-Report-Only (optional)
        inline_scripts: list of inline <script> bodies
        external_scripts: dict of {url: source_code} for external .js

    Returns TrustedTypesReport.
    """
    report = TrustedTypesReport(url=url)

    # CSP analysis (prefer enforced over report-only)
    if csp_header:
        report.csp_info = analyze_csp_header(csp_header, report_only=False)
    elif csp_report_only:
        report.csp_info = analyze_csp_header(csp_report_only, report_only=True)

    # Policy audits — audit all sources regardless of CSP, because some apps
    # use TT polyfill without CSP
    for body in (inline_scripts or []):
        report.policy_findings.extend(
            audit_policy_definitions(body, source_name=url + "#inline")
        )
    for ext_url, src in (external_scripts or {}).items():
        report.policy_findings.extend(
            audit_policy_definitions(src, source_name=ext_url)
        )

    return report


# ══════════════════════════════════════════════════════════════════════════════
# RUNTIME POLICY AUDIT (v10.72)
# ══════════════════════════════════════════════════════════════════════════════
# Complements the static audit above: the dom_hooks_v6.js runtime hook wraps
# trustedTypes.createPolicy and PROBES each registered policy's transformers with
# a dangerous string. Static analysis can't see what a minified/obfuscated
# transformer actually does; this observes the real behavior. A pass-through
# policy is a no-op sanitizer; a pass-through 'default' policy is a silent
# backdoor satisfying Trusted Types for EVERY sink while sanitizing nothing.

# v10.74 FP-cut: known-safe library / framework Trusted Types policies. These
# are type-bridge or vendor policies that return input unchanged BY DESIGN — the
# security is enforced upstream (e.g. Google's goog#html only ever receives an
# already-typed SafeHtml value; the policy just bridges it into Trusted Types).
# Probing them with a raw string always LOOKS pass-through but is never an
# exploitable app backdoor. They're injected by Google Translate/GTM/reCAPTCHA,
# Angular, webpack, etc. — not the site's own code. Suppress entirely.
_KNOWN_SAFE_TT_POLICY_NAMES = frozenset({
    "dompurify",          # DOMPurify's own sanitizing policy
    "lit-html", "lit",    # Lit
    "webpack",            # webpack runtime policy
    "nextjs", "next",     # Next.js
})
_KNOWN_SAFE_TT_POLICY_PREFIXES = (
    "goog#",              # Google Closure / safevalues type bridges (goog#html, goog#script, …)
    "angular#",           # Angular framework-internal policies (unsafe-bypass handled by static escape-hatch detection)
)


def _is_known_safe_tt_policy(name: str) -> bool:
    n = (name or "").strip().lower()
    if not n:
        return False
    if any(n.startswith(pfx) for pfx in _KNOWN_SAFE_TT_POLICY_PREFIXES):
        return True
    return n in _KNOWN_SAFE_TT_POLICY_NAMES


# Corrected severity matrix (v10.75). A pass-through Trusted Types policy is a
# CONFIGURATION WEAKNESS, not a confirmed DOM XSS — the runtime probe proves the
# transformer is a no-op, NOT that any attacker-controlled string reaches a sink
# through it. So these findings are reported as unconfirmed candidates (fp_risk,
# verification_required) and NEVER as browser-proven exploits (no dom_verified),
# with severities keyed on two facts the old model ignored:
#   * enforced — is `require-trusted-types-for 'script'` ACTUALLY active? If not,
#     the 'default' policy is never auto-invoked and the "backdoor" is inert:
#     zero security effect, so we suppress the finding (was the biggest FP).
#   * default vs named — only the 'default' policy is auto-applied to every sink;
#     a named policy only matters if the app explicitly routes untrusted input
#     through it, which the probe cannot confirm → informational.
# Severities never reach 'critical': that is reserved for a confirmed
# source→sink flow, which this static/runtime probe does not establish.
#   key = (transformer, is_default, enforced_true)
_TT_RUNTIME_SEVERITY = {
    # createHTML
    ("createHTML",    True,  True):  "medium",
    ("createHTML",    True,  False): "low",     # enforcement UNKNOWN (None)
    ("createHTML",    False, True):  "info",
    ("createHTML",    False, False): "info",
    # createScript — eval-equivalent, one notch worse
    ("createScript",  True,  True):  "high",
    ("createScript",  True,  False): "medium",
    ("createScript",  False, True):  "low",
    ("createScript",  False, False): "low",
    # createScriptURL — loads arbitrary script
    ("createScriptURL", True,  True):  "medium",
    ("createScriptURL", True,  False): "low",
    ("createScriptURL", False, True):  "info",
    ("createScriptURL", False, False): "info",
}


def analyze_runtime_tt_policies(policies, page_url: str = "", enforced=None):
    """Turn the runtime `tt_policies` records (from __xssg_state__) into
    engine-standard finding dicts. `policies` is a list of dicts with keys:
    name, passthrough_html, passthrough_script, passthrough_scripturl.

    `enforced` is a tri-state (True / False / None) — whether the page actually
    enforces `require-trusted-types-for 'script'`, as detected by the runtime
    hook (behavioral innerHTML probe + meta-CSP scan).

    Severity model (v10.75 — FP fix). The old model rated a pass-through
    'default' policy as **critical DOM XSS** and marked it browser-verified.
    That was wrong on three counts, so it is corrected here:
      1. A pass-through policy is only a backdoor when TT is ENFORCED. With
         `enforced is False` the default policy is never auto-invoked, so the
         finding is SUPPRESSED (returning it was a pure false positive — the
         page is exactly as (un)protected as one with no Trusted Types at all,
         which the CSP analyzer itself rates merely 'info').
      2. Even when enforced, a pass-through policy is a weakened-defense
         MISCONFIGURATION, not a proven exploit — there is no confirmed
         source→sink flow — so severity tops out at 'high' (createScript, the
         eval-equivalent case) and these are flagged fp_risk / verification-
         required, never 'critical'.
      3. What the probe DID confirm is only that the transformer is a no-op
         (`tt_probe_confirmed`), NOT that XSS fires — so the caller must not set
         dom_verified on these.
    Known-safe vendor policies (goog#html etc.) are suppressed entirely."""
    out = []
    seen = set()
    enforced_true = (enforced is True)
    for p in (policies or []):
        try:
            name = str(p.get("name", "?"))
        except Exception:
            continue
        if _is_known_safe_tt_policy(name):
            continue
        is_default = (name == "default")

        # Enforcement gate: a pass-through policy on a page that does NOT enforce
        # `require-trusted-types-for 'script'` has no security effect at all —
        # the transformer is never on the enforced path. Suppress it.
        if enforced is False:
            continue

        enf_note = (
            "Trusted Types IS enforced on this page (require-trusted-types-for "
            "'script')." if enforced_true else
            "NOTE: enforcement of require-trusted-types-for 'script' could not be "
            "confirmed at runtime — if TT is not actually enforced this is inert.")

        def _add(kind, why):
            key = (name, kind)
            if key in seen:
                return
            seen.add(key)
            sev = _TT_RUNTIME_SEVERITY.get((kind, is_default, enforced_true), "info")
            out.append({
                "url": page_url,
                "param": "Trusted Types policy '%s'" % name,
                "payload": "trustedTypes.createPolicy('%s', {%s: passthrough})" % (name, kind),
                "context": "trusted-types-runtime-%s" % kind.lower(),
                "source": "trusted-types-runtime",
                "severity": sev,
                # one finding per (policy,transformer) — a policy created on N
                # crawled pages must NOT emit N times. Engine dedups on this.
                "dedup_url": "tt:%s:%s" % (name, kind),
                # CWE-1173 (improper use of validation framework) is the honest
                # class here — the defect is a neutered sanitization policy. It is
                # not CWE-79 until an actual injection through it is demonstrated.
                "cwe_hint": "CWE-1173",
                "policy": name,
                "transformer": kind,
                # Honest confidence signalling — this is a CANDIDATE misconfig,
                # not a proven exploit. Keeps the scorer/store from treating it
                # as a browser-confirmed unique-nonce XSS.
                "tt_probe_confirmed": True,     # what we DID confirm: no-op transformer
                "verification_required": True,  # exploitability NOT confirmed
                "fp_risk": True,
                "fp_reason": ("Trusted Types pass-through policy is a configuration "
                              "weakness; no attacker-controlled source→sink flow "
                              "through it was confirmed."),
                "tt_enforced": enforced,
                "evidence": (
                    "Runtime probe: policy '%s' %s returned the dangerous probe "
                    "UNCHANGED — it is a pass-through (no-op) transformer.%s %s" % (
                        name, kind,
                        (" As the 'default' policy it is auto-applied to every "
                         "sink on the page." if is_default else
                         " This is a NAMED (opt-in) policy — it only matters if "
                         "the app routes untrusted input through it."),
                        enf_note)),
                "description": (
                    "Trusted Types is meant to force all %s sinks through a "
                    "sanitizing policy, but this policy's %s passes input through "
                    "unchanged (%s). %s This is a defense-in-depth weakness, not a "
                    "confirmed injection — verify whether attacker-controlled data "
                    "can reach a sink via this policy. Fix the transformer to "
                    "actually sanitize (e.g. return DOMPurify.sanitize(input)) or "
                    "remove the pass-through 'default' policy." % (
                        kind.replace("create", "").lower(), kind, why,
                        "As the DEFAULT policy it neutralizes Trusted Types "
                        "protection for every sink on the page."
                        if is_default else
                        "Any sink that uses this named policy is unprotected.")),
            })

        if p.get("passthrough_html") is True:
            _add("createHTML", "an <img onerror> probe survived intact")
        if p.get("passthrough_script") is True:
            _add("createScript", "a script-body probe survived intact → eval-equivalent")
        if p.get("passthrough_scripturl") is True:
            _add("createScriptURL", "an arbitrary script URL survived intact → loads any script")
    return out
