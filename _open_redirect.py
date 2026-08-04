"""Open Redirect → XSS chain detection (v10.11).

Open redirect is often dismissed as low severity, but when the redirect
target allows `javascript:` schema, it becomes a stored/reflected XSS vector.

Two detection strategies:

  STRATEGY A (network-based) — `_test_open_redirect_endpoint()`:
    1. Crawler discovers URL params matching redirect patterns
       (?url=, ?redirect=, ?next=, ?return=, ?dest=, ?goto=, etc.)
    2. Engine sends payload with `javascript:` schema
    3. Server response examined for:
       a. HTTP 30x with Location: javascript:...  → CRITICAL (server redirect)
       b. HTML <a href="javascript:..."> or <meta http-equiv="refresh">
          → HIGH (client-side redirect via HTML)
       c. JS code: window.location = "javascript:..."
          → HIGH (client-side redirect via JS)

  STRATEGY B (static AST) — `_detect_static_redirect_sinks()`:
    1. Parse JS source via esprima
    2. Find patterns:
       - window.location = userInput / window.location.href = userInput
       - location.replace(userInput) / location.assign(userInput)
       - history.pushState(state, title, userInput)
    3. Where userInput is traceable to URL params, hash, or form fields
       → flag as potential open redirect → XSS

Detection is opt-in (--open-redirect flag) and runs after crawl phase.
Cost: ~1 HTTP request per redirect candidate (typically 5-20 per site).
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse, unquote


# ── PUBLIC API ────────────────────────────────────────────────────────────────

# Common URL parameter names used for redirects (case-insensitive).
# Curated from real-world bug bounty reports (HackerOne, Bugcrowd, Intigriti)
# and OWASP Cheat Sheet Series.
REDIRECT_PARAM_NAMES: Set[str] = {
    # Standard redirect names
    "url", "redirect", "redirect_to", "redirecturl", "redirect_url",
    "redirect_uri", "redir", "destination", "dest", "next", "goto",
    "return", "returnto", "return_to", "returnurl", "return_url",
    "continue", "forward", "forward_url", "callback", "callback_url",
    "callbackurl", "target", "target_url", "to", "go", "page",
    # OAuth / SSO patterns
    "redirect_uri", "post_logout_redirect_uri", "logout_redirect",
    "success_url", "failure_url", "cancel_url", "error_url",
    # Login flow
    "login_redirect", "after_login", "afterlogin", "from",
    # Less common but seen in wild
    "out", "exit", "ref", "referer", "referrer",  # ref-like may be misused
    "link", "site", "domain", "host", "u",
    # E-commerce specific
    "checkout_url", "shop_redirect", "buy_url",
}

# JavaScript schema variants that lead to XSS when used in href/location.
# Browsers normalize these — DETECTION must catch ALL variants attackers use.
JS_SCHEMA_PATTERNS: List[re.Pattern] = [
    # Plain javascript:
    re.compile(r"^\s*javascript\s*:", re.IGNORECASE),
    # With encoded colon (older browsers)
    re.compile(r"^\s*javascript\s*&colon;", re.IGNORECASE),
    re.compile(r"^\s*javascript\s*%3a", re.IGNORECASE),
    # Tab/newline injected (CRLF-style obfuscation)
    re.compile(r"^\s*j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:",
               re.IGNORECASE | re.MULTILINE),
    # data: URLs that can execute (less common but seen)
    re.compile(r"^\s*data\s*:\s*text/html", re.IGNORECASE),
    # vbscript: (IE legacy)
    re.compile(r"^\s*vbscript\s*:", re.IGNORECASE),
]

# JS sink patterns for STRATEGY B (static AST analysis).
# These property/method accesses, when assigned user input, can execute JS.
_JS_REDIRECT_SINKS = {
    # Property assignments
    "location.href", "location",
    "window.location", "window.location.href",
    "document.location", "document.location.href",
    "top.location", "parent.location",
    # Method calls
    "location.replace", "location.assign",
    "window.open",
    "history.pushState", "history.replaceState",
}


@dataclass
class OpenRedirectFinding:
    """A detected open redirect / open redirect → XSS chain."""
    url: str                            # Tested URL
    param: str                          # Vulnerable parameter name
    method: str                         # "GET" / "POST"
    redirect_kind: str                  # "server-30x" / "meta-refresh" / "html-href" / "js-location"
    is_xss_chain: bool                  # True if javascript: schema accepted
    payload: str                        # Payload used
    response_status: int = 0
    location_header: Optional[str] = None
    snippet: Optional[str] = None       # Reflected HTML/JS snippet
    severity: str = "medium"            # critical / high / medium / low
    confidence: float = 0.7
    note: str = ""


@dataclass
class StaticRedirectSink:
    """A static AST finding: redirect sink assigned user-controlled data."""
    file: str
    line: int
    sink_name: str                      # e.g. "window.location.href"
    source_pattern: str                 # e.g. "location.search.split" or "URLSearchParams.get"
    snippet: str = ""
    severity: str = "medium"            # high if source clearly user-controllable
    confidence: float = 0.6


# ── Helper functions ──────────────────────────────────────────────────────────

def _is_likely_redirect_param(param_name: str) -> bool:
    """Case-insensitive match against REDIRECT_PARAM_NAMES."""
    if not param_name:
        return False
    return param_name.lower() in REDIRECT_PARAM_NAMES


def _is_js_schema_url(url: str) -> bool:
    """True if URL uses javascript: or other executable schema.

    Decodes URL-encoded forms (%0a → newline, %20 → space) before matching,
    so attacker obfuscation like `java%0ascript:alert(1)` is caught.
    """
    if not url:
        return False
    # First check raw form (most common case)
    for rx in JS_SCHEMA_PATTERNS:
        if rx.match(url):
            return True
    # Then decode URL-encoded characters and check again. This catches
    # `java%0ascript:` and similar obfuscation. We use unquote_plus
    # (handles + as space too) — some servers normalize this way.
    try:
        from urllib.parse import unquote_plus
        decoded = unquote_plus(url)
        if decoded != url:
            for rx in JS_SCHEMA_PATTERNS:
                if rx.match(decoded):
                    return True
    except Exception:
        pass
    return False


def find_redirect_params(url: str) -> List[Tuple[str, str]]:
    """Extract (param_name, original_value) pairs that look like redirect params.

    Returns list of tuples — caller can then test each with a payload.
    """
    if not url:
        return []
    try:
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
    except Exception:
        return []
    return [(name, val) for name, val in params if _is_likely_redirect_param(name)]


def build_redirect_test_url(url: str, param: str, payload: str) -> str:
    """Build test URL with payload injected into param. Preserves other params."""
    try:
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        new_params: List[Tuple[str, str]] = []
        for name, val in params:
            if name == param:
                new_params.append((name, payload))
            else:
                new_params.append((name, val))
        new_query = urlencode(new_params)
        return urlunparse(parsed._replace(query=new_query))
    except Exception:
        return url


# ── STRATEGY A: Network-based detection ───────────────────────────────────────

# HTML patterns for client-side redirect detection
_RE_META_REFRESH = re.compile(
    r"""<meta\s+[^>]*http-equiv\s*=\s*['"]?refresh['"]?[^>]*content\s*=\s*['"]?\s*\d+\s*;\s*url\s*=\s*([^'">\s]+)""",
    re.IGNORECASE | re.DOTALL
)
_RE_LINK_HREF_JS = re.compile(
    r"""<a\s+[^>]*href\s*=\s*['"]?\s*(javascript:[^'">\s]*)""",
    re.IGNORECASE | re.DOTALL
)
_RE_JS_LOCATION_ASSIGN = re.compile(
    r"""(?:window\s*\.\s*)?(?:document\s*\.\s*)?location(?:\s*\.\s*href)?\s*=\s*['"]?(javascript:[^'"`;\s]+)""",
    re.IGNORECASE
)


def analyze_redirect_response(
    response_status: int,
    location_header: Optional[str],
    response_body: Optional[str],
    payload: str,
) -> Optional[Tuple[str, str, str]]:
    """Examine response for evidence the payload triggered a redirect.

    Returns (redirect_kind, evidence_snippet, severity) or None.
    """
    # Strategy: 30x with javascript: Location header (CRITICAL — server reflects)
    if response_status and 300 <= response_status < 400:
        if location_header and _is_js_schema_url(location_header):
            return ("server-30x",
                    f"Location: {location_header[:120]}",
                    "critical")
        # Any open redirect (even non-JS) is medium — BUT only when the payload is
        # the actual redirect DESTINATION, not merely reflected inside a query
        # param of a same-origin path. v10.80 FP fix: login-return and
        # canonicalization 30x preserve `?next=<payload>` on a same-origin path
        # (GET /account?next=javascript:alert(1) -> 302 /login?next=javascript:...);
        # that is benign, yet the old substring test flagged every one of them.
        if location_header and payload and payload[:40] in location_header:
            _only_in_query = False
            try:
                _lp = urlparse(location_header)
                _dest = f"{_lp.scheme}://{_lp.netloc}{_lp.path}"
                _only_in_query = (payload[:40] in (_lp.query or "")
                                  and payload[:40] not in _dest)
            except Exception:
                _only_in_query = False
            if not _only_in_query:
                return ("server-30x-open",
                        f"Location: {location_header[:120]}",
                        "medium")

    if not response_body:
        return None

    # v10.80 FN fix: also scan a URL-decoded + control-char-stripped copy, so the
    # scheme-obfuscation bypasses the scanner itself sends (java%0ascript:,
    # java<TAB>script:) are detected even when the server reflects only the
    # obfuscated form. Browsers strip those control chars from the scheme, so
    # `java\tscript:` IS executable — our literal-`javascript:` regexes are not.
    _scan_bodies = [response_body]
    try:
        _norm = unquote(response_body).translate(
            {0x09: None, 0x0a: None, 0x0d: None, 0x00: None})
        if _norm != response_body:
            _scan_bodies.append(_norm)
    except Exception:
        pass

    # only flag if OUR payload marker made it in — sites have legitimate
    # javascript:void(0) handlers and we don't want FP on those.
    payload_short = payload[:30] if payload else ""
    payload_marker = "alert(1)" if "alert(1)" in payload else (
        "alert(document.domain)" if "alert(document.domain)" in payload
        else payload_short
    )

    for _body in _scan_bodies:
        # Strategy: <meta http-equiv="refresh" content="0; url=javascript:...">
        # v10.80: gate on payload reflection (like the href/location branches) and
        # downgrade — browsers do NOT execute javascript: in a meta-refresh, so it
        # is a reflected-scheme signal, not a confirmed XSS chain.
        for m in _RE_META_REFRESH.finditer(_body):
            ref_url = m.group(1)
            if (_is_js_schema_url(ref_url)
                    and payload_marker and payload_marker in ref_url):
                return ("meta-refresh",
                        f'<meta refresh URL={ref_url[:120]}>',
                        "medium")

        # Strategy: <a href="javascript:..."> with payload reflected
        for m in _RE_LINK_HREF_JS.finditer(_body):
            href = m.group(1)
            if payload_marker and payload_marker in href:
                return ("html-href",
                        f'<a href="{href[:120]}">',
                        "high")

        # Strategy: JS code does location = "javascript:..." with payload reflected
        for m in _RE_JS_LOCATION_ASSIGN.finditer(_body):
            js_target = m.group(1)
            if payload_marker and payload_marker in js_target:
                return ("js-location",
                        f'JS: location = {js_target[:120]}',
                        "high")

    return None


def test_open_redirect_endpoint(
    fetcher,
    url: str,
    param: str,
    timeout: float = 10.0,
    follow_redirects: bool = False,
) -> Optional[OpenRedirectFinding]:
    """Test a single (URL, param) for open redirect → XSS.

    fetcher: callable(url, allow_redirects, timeout) → response object with:
             .status_code, .headers, .text
    Returns OpenRedirectFinding if vulnerable, None otherwise.
    """
    # Payloads to test — start with most "obvious" javascript:alert(1),
    # then encoded variants to catch filters
    payloads = [
        "javascript:alert(1)",
        "javascript:alert(document.domain)",
        # Encoded variants (some servers filter only literal "javascript:")
        "java%0ascript:alert(1)",       # \n in middle
        "java\tscript:alert(1)",         # tab
        "JaVaScRiPt:alert(1)",           # case
    ]

    for payload in payloads:
        test_url = build_redirect_test_url(url, param, payload)
        try:
            r = fetcher(test_url, allow_redirects=False, timeout=timeout)
        except Exception as e:
            logging.debug(f"open_redirect fetch error for {test_url}: {e}")
            continue

        if not r:
            continue

        # Extract response components
        try:
            status = r.status_code
            location = r.headers.get("Location") or r.headers.get("location")
            body = r.text if hasattr(r, "text") else ""
        except Exception:
            continue

        analysis = analyze_redirect_response(status, location, body, payload)
        if not analysis:
            continue

        kind, snippet, severity = analysis
        return OpenRedirectFinding(
            url=url,
            param=param,
            method="GET",
            redirect_kind=kind,
            is_xss_chain=(severity in ("critical", "high")),
            payload=payload,
            response_status=status,
            location_header=location,
            snippet=snippet,
            severity=severity,
            confidence=0.85 if severity == "critical" else 0.7,
            note=f"javascript: schema reflected via {kind}",
        )

    return None


# ── STRATEGY B: Static AST detection ──────────────────────────────────────────

try:
    import esprima
    _ESPRIMA_AVAILABLE = True
except ImportError:
    _ESPRIMA_AVAILABLE = False


# Source patterns that suggest user-controlled input
_USER_INPUT_SOURCE_PATTERNS = [
    "location.search", "location.hash", "location.pathname",
    "document.URL", "document.documentURI", "document.referrer",
    "URLSearchParams", "window.name",
    # Form values
    ".value", ".getAttribute",
    # localStorage / sessionStorage (less common but seen)
    "localStorage.getItem", "sessionStorage.getItem",
]


def _node_type(node) -> str:
    """Safe accessor for esprima node type (handles AttributeError)."""
    try:
        return getattr(node, "type", "") or ""
    except Exception:
        return ""


def _flatten_member_expr(node) -> str:
    """Convert MemberExpression AST node to flat string like 'a.b.c'."""
    if _node_type(node) == "Identifier":
        return getattr(node, "name", "") or ""
    if _node_type(node) == "MemberExpression":
        obj_part = _flatten_member_expr(node.object)
        prop = node.property
        prop_name = ""
        if _node_type(prop) == "Identifier":
            prop_name = getattr(prop, "name", "") or ""
        elif _node_type(prop) == "Literal":
            prop_name = str(getattr(prop, "value", ""))
        if obj_part and prop_name:
            return f"{obj_part}.{prop_name}"
        return obj_part or prop_name
    if _node_type(node) == "CallExpression":
        return _flatten_member_expr(node.callee)
    return ""


def _expression_contains_user_input(node, source_snippet: str = "",
                                     full_source: str = "") -> bool:
    """Check if expression references user-input sources (heuristic).

    Strategy:
      1. Direct match: expression flattened to string vs known patterns
      2. Snippet match: same-line source contains user-input pattern
      3. Variable tracking (lightweight): if expression is Identifier `var`,
         search full_source for `var = …userInput…` patterns
    """
    if not node:
        return False
    flat = _flatten_member_expr(node)
    # Direct match against known patterns
    for pat in _USER_INPUT_SOURCE_PATTERNS:
        if pat in flat:
            return True
    # Snippet-based fallback for complex expressions on same line
    if source_snippet:
        for pat in _USER_INPUT_SOURCE_PATTERNS:
            if pat in source_snippet:
                return True
    # Variable tracking — if expression is just a variable name,
    # look for its declaration in the full source. This is lightweight
    # (no real data-flow analysis) but catches simple cases like:
    #   const next = params.get('next');
    #   window.location.href = next;
    # AND multi-step:
    #   const params = new URLSearchParams(location.search);
    #   const next = params.get('next');
    #   window.location.href = next;  ← `next` traced back to `params` traced to `location.search`
    if full_source and _node_type(node) == "Identifier":
        var_name = getattr(node, "name", "")
        if var_name and len(var_name) > 1:  # skip 'a', 'b', 'i' etc.
            import re as _re
            # Strategy 1: direct match — `<var> = ... pat ...`
            for pat in _USER_INPUT_SOURCE_PATTERNS:
                escaped = _re.escape(pat)
                rx = _re.compile(
                    rf"\b(?:const|let|var)?\s*{_re.escape(var_name)}\s*=[^;]*{escaped}",
                    _re.MULTILINE
                )
                if rx.search(full_source):
                    return True
            # Strategy 2: indirect match — find `<var> = OTHER_VAR.something(...)`,
            # then check if OTHER_VAR was assigned from user input.
            # Capture: const next = params.get('next');  →  params
            indirect_rx = _re.compile(
                rf"\b(?:const|let|var)?\s*{_re.escape(var_name)}\s*=\s*(\w+)\.",
                _re.MULTILINE
            )
            for m in indirect_rx.finditer(full_source):
                other_var = m.group(1)
                if not other_var or len(other_var) <= 1:
                    continue
                # Check if other_var was assigned from user input
                for pat in _USER_INPUT_SOURCE_PATTERNS:
                    escaped = _re.escape(pat)
                    rx2 = _re.compile(
                        rf"\b(?:const|let|var)?\s*{_re.escape(other_var)}\s*=[^;]*{escaped}",
                        _re.MULTILINE
                    )
                    if rx2.search(full_source):
                        return True
    return False


def detect_static_redirect_sinks(
    source_code: str,
    source_name: str = "<inline>",
) -> List[StaticRedirectSink]:
    """Find redirect sinks assigned user input in JS source code.

    Returns list of StaticRedirectSink. Uses esprima AST for accuracy.
    Falls back to empty list if esprima unavailable.
    """
    if not _ESPRIMA_AVAILABLE or not source_code or not source_code.strip():
        return []
    try:
        tree = esprima.parseScript(
            source_code, options={"loc": True, "range": True, "tolerant": True}
        )
    except Exception:
        try:
            tree = esprima.parseModule(
                source_code, options={"loc": True, "range": True, "tolerant": True}
            )
        except Exception:
            return []

    findings: List[StaticRedirectSink] = []
    source_lines = source_code.split("\n")

    def get_snippet(loc) -> str:
        try:
            line_idx = loc.start.line - 1
            if 0 <= line_idx < len(source_lines):
                return source_lines[line_idx].strip()[:200]
        except Exception:
            pass
        return ""

    def visit(node):
        t = _node_type(node)

        # Pattern 1: AssignmentExpression — location.href = userInput
        if t == "AssignmentExpression":
            left = node.left
            right = node.right
            sink_name = _flatten_member_expr(left)
            if any(s in sink_name for s in _JS_REDIRECT_SINKS):
                snippet = get_snippet(node.loc) if hasattr(node, "loc") else ""
                if _expression_contains_user_input(right, snippet, source_code):
                    findings.append(StaticRedirectSink(
                        file=source_name,
                        line=node.loc.start.line if hasattr(node, "loc") else 0,
                        sink_name=sink_name,
                        source_pattern=_flatten_member_expr(right) or "<expr>",
                        snippet=snippet,
                        severity="high" if "location" in sink_name else "medium",
                        confidence=0.75,
                    ))

        # Pattern 2: CallExpression — location.replace(userInput) / open(...)
        if t == "CallExpression":
            callee = node.callee
            callee_str = _flatten_member_expr(callee)
            sink_match = None
            for s in _JS_REDIRECT_SINKS:
                if s in callee_str and "." in s:  # only method calls here
                    sink_match = s
                    break
            if sink_match:
                args = node.arguments or []
                # For window.open and history.pushState, target URL is in different arg
                target_arg = args[0] if args else None
                if "pushState" in callee_str or "replaceState" in callee_str:
                    target_arg = args[2] if len(args) > 2 else None
                if target_arg:
                    snippet = get_snippet(node.loc) if hasattr(node, "loc") else ""
                    if _expression_contains_user_input(target_arg, snippet, source_code):
                        findings.append(StaticRedirectSink(
                            file=source_name,
                            line=node.loc.start.line if hasattr(node, "loc") else 0,
                            sink_name=callee_str,
                            source_pattern=_flatten_member_expr(target_arg) or "<expr>",
                            snippet=snippet,
                            severity="high",
                            confidence=0.7,
                        ))

        # Recurse into children
        for attr in dir(node):
            if attr.startswith("_") or attr in ("type", "loc", "range"):
                continue
            try:
                v = getattr(node, attr)
            except Exception:
                continue
            if v is None:
                continue
            if isinstance(v, list):
                for item in v:
                    if hasattr(item, "type"):
                        visit(item)
            elif hasattr(v, "type"):
                visit(v)

    try:
        visit(tree)
    except Exception as e:
        logging.debug(f"AST walk error in {source_name}: {e}")

    return findings


# ── Helper for engine integration ─────────────────────────────────────────────

def discover_redirect_candidates(crawled_urls: List[str]) -> List[Tuple[str, str]]:
    """Scan crawled URLs for redirect-param candidates.

    Returns deduplicated list of (url, param_name) tuples.
    Engine uses this to drive test_open_redirect_endpoint().
    """
    seen: Set[Tuple[str, str]] = set()
    candidates: List[Tuple[str, str]] = []
    for url in crawled_urls or []:
        for param, _ in find_redirect_params(url):
            try:
                # Normalize: scheme+host+path (drop query for dedup)
                u = urlparse(url)
                norm = f"{u.scheme}://{u.netloc}{u.path}"
            except Exception:
                norm = url
            key = (norm, param)
            if key not in seen:
                seen.add(key)
                candidates.append((url, param))
    return candidates
