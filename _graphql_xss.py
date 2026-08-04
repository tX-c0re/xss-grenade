"""
_graphql_xss.py — GraphQL injection / reflected-XSS detection (v10.51).

Why this module exists (XSS scanner 2026)
─────────────────────────────────────────
Modern apps expose a single GraphQL endpoint (`/graphql`, `/api/graphql`, …)
instead of many REST routes. Crawl-based and query-string scanners walk straight
past it: there are no URL parameters to fuzz — the attack surface lives inside a
JSON POST body (`query` / `variables`). Two high-value, frequently-missed XSS
vectors live here:

  1. **Error-message reflection.** A malformed query echoes the offending
     fragment back verbatim:
         {"errors":[{"message":"Cannot query field \"<svg/onload=…>\" on Query"}]}
     Apollo Sandbox, GraphiQL and many home-grown error panels render that
     message as HTML → reflected XSS. If the `<` survives unescaped in the
     response, the payload would execute when the message is shown.

  2. **String-variable / argument reflection.** A canary fed through a String
     variable (or inline argument) comes back inside `data` unescaped and is
     later dropped into the DOM by the client (innerHTML of a comment, name,
     search term, …) → reflected/stored XSS.

This module is intentionally dependency-light (requests + json + re) and
degrades gracefully: if the endpoint isn't GraphQL, every probe returns nothing.

Design contract
───────────────
- Read-only probing: it sends *queries* (and deliberately malformed ones). It
  never sends mutations, so it cannot change server state.
- Findings use the same dict shape as the other network phases (jsonp/svg), so
  the engine's single `_emit_hit` chokepoint (dedup → v2 gate → emit) handles
  them with zero special-casing. `response_body` + `content_type` are included
  so the v2 gate can downgrade non-renderable reflections.
"""
from __future__ import annotations

import json
import re
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse, urlunparse


# ── Endpoint discovery ───────────────────────────────────────────────────────
GRAPHQL_PATH_HINTS = (
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/query", "/api/query", "/gql", "/api/gql", "/graphql/console",
)

# Common GraphQL mount points to *try* when the crawler only found the host.
GRAPHQL_PROBE_PATHS = ("/graphql", "/api/graphql", "/query", "/gql")

_JSON_CT = ("application/json", "application/graphql-response+json",
            "application/graphql+json")


def looks_like_graphql_url(url: str) -> bool:
    """Cheap path-based heuristic — does the URL look like a GraphQL endpoint?"""
    try:
        path = (urlparse(url).path or "").lower()
    except Exception:
        return False
    return any(h in path for h in GRAPHQL_PATH_HINTS)


def _post_json(session, url: str, payload: dict, timeout: float,
               follow_redirects: bool):
    """POST a JSON body; return the requests.Response or None on network error."""
    try:
        return session.post(
            url,
            json=payload,
            timeout=timeout,
            allow_redirects=follow_redirects,
            headers={"Accept": "application/json, */*"},
        )
    except Exception:
        return None


def _is_graphql_response(resp) -> bool:
    """A GraphQL server answers `{query}` with a JSON object carrying `data`
    or `errors` at the top level. That shape is our positive signal."""
    if resp is None:
        return False
    ct = (resp.headers.get("Content-Type", "") or "").lower()
    body = resp.text or ""
    if not body:
        return False
    # Content-type is a hint but not required (some servers send text/html for
    # errors); the JSON *shape* is the real discriminator.
    try:
        obj = json.loads(body)
    except Exception:
        return False
    if not isinstance(obj, dict):
        return False
    if "data" in obj or "errors" in obj:
        # Guard against generic JSON APIs that happen to have a "data" key:
        # require either a GraphQL-style error or a recognizable typed result.
        if "errors" in obj and isinstance(obj.get("errors"), list):
            return True
        if "data" in obj:
            # data may legitimately be null on an error-only response
            return True
    _ = ct  # kept for readability; shape check above is authoritative
    return False


# GraphQL validation/execution errors use a recognizable vocabulary. A generic
# REST 404 that merely happens to return {"errors":[...]} won't contain these.
# NOTE: keep these GraphQL-SPECIFIC. A bare "graphql" term matched the echoed
# probe path in a non-GraphQL 404 (e.g. Express: {"errors":[{"message":"Cannot
# POST /graphql"}]}) → false endpoint. "did you mean" is also too generic. A real
# GraphQL server resolves {__typename} (caught by _resolves_typename's data check),
# so dropping these from the error-vocabulary fallback does not lose recall.
_GQL_ERROR_TERMS = re.compile(
    r"__typename|cannot query field|must provide an operation|"
    r"expected name|unknown argument|on type \"|"
    r"validation error of type|graphql syntax error",
    re.IGNORECASE,
)


def _resolves_typename(resp) -> bool:
    """Strict GraphQL confirmation: the introspection meta-field `__typename`
    either resolves under `data`, or the server answers with a genuine GraphQL
    validation error (not just any errors-shaped JSON). This rejects REST APIs
    whose 404 body coincidentally looks like {"errors":[...]}."""
    if resp is None:
        return False
    try:
        obj = json.loads(resp.text or "")
    except Exception:
        return False
    if not isinstance(obj, dict):
        return False
    data = obj.get("data")
    if isinstance(data, dict) and "__typename" in data:
        return True
    errs = obj.get("errors")
    if isinstance(errs, list) and errs:
        joined = " ".join(str(e.get("message", "")) if isinstance(e, dict)
                          else str(e) for e in errs)
        return bool(_GQL_ERROR_TERMS.search(joined))
    return False


def probe_is_graphql(session, url: str, timeout: float,
                     follow_redirects: bool) -> bool:
    """Confirm an endpoint speaks GraphQL by sending the `{__typename}` meta
    query and requiring genuine GraphQL semantics in the answer (resolved
    `__typename` or a GraphQL validation error) — not just a JSON shape."""
    resp = _post_json(session, url, {"query": "{__typename}"},
                      timeout, follow_redirects)
    if _resolves_typename(resp):
        return True
    # Some servers reject the anonymous shorthand; retry with a named query.
    resp = _post_json(session, url, {"query": "query Ping { __typename }"},
                      timeout, follow_redirects)
    return _resolves_typename(resp)


def discover_graphql_endpoints(session, base_url: str, timeout: float,
                               follow_redirects: bool,
                               extra_urls: Optional[List[str]] = None
                               ) -> List[str]:
    """Return the list of confirmed GraphQL endpoints reachable from base_url.

    Strategy: test any crawler-supplied URL that *looks* like GraphQL, plus a
    short list of conventional mount points on the target origin. Every
    candidate is confirmed with `probe_is_graphql` so we never inject into a
    non-GraphQL endpoint."""
    candidates: List[str] = []
    for u in (extra_urls or []):
        if looks_like_graphql_url(u):
            candidates.append(u)
    try:
        p = urlparse(base_url)
        origin = urlunparse((p.scheme, p.netloc, "", "", "", ""))
    except Exception:
        origin = base_url.rstrip("/")
    for path in GRAPHQL_PROBE_PATHS:
        candidates.append(origin + path)

    seen, confirmed = set(), []
    for u in candidates:
        key = u.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        try:
            if probe_is_graphql(session, u, timeout, follow_redirects):
                confirmed.append(u)
        except Exception:
            continue
    return confirmed


# ── Injection probes ─────────────────────────────────────────────────────────
# Self-firing canary: a marker the caller can grep for, wrapped in a payload
# that, if reflected raw into HTML, becomes an executing element. The literal
# `<` / `>` / `"` are what the v2 gate (and our raw-reflection check) keys on —
# if the server HTML-escapes them, it's inert and we down-rank / drop it.
def _xss_payload(marker: str) -> str:
    return f'<svg/onload=alert("{marker}")>'


def _raw_reflected(body: str, payload: str, marker: str) -> bool:
    """True only if the dangerous form survives. We require the marker AND at
    least one unescaped angle bracket from the payload near it — an escaped
    `&lt;svg…` is not exploitable and must not be reported."""
    if marker not in body:
        return False
    # The payload (or its leading `<svg/onload=`) must appear unescaped.
    return "<svg/onload=" in body or payload in body


def scan_graphql_xss(session, url: str, timeout: float,
                     follow_redirects: bool,
                     marker_factory: Callable[[], str]) -> List[Dict]:
    """Probe a confirmed GraphQL endpoint for reflected-XSS vectors.

    Returns a (possibly empty) list of finding dicts in the engine's standard
    shape. Two vectors are tested:

      A) error-message reflection — a malformed field name carrying the payload
      B) string-variable reflection — the payload fed through a String variable

    The caller is responsible for confirming `url` is GraphQL first (use
    `discover_graphql_endpoints`)."""
    findings: List[Dict] = []

    # ── Vector A: error-message reflection ──────────────────────────────────
    # An invalid field name containing the payload. GraphQL validators echo the
    # unknown-field text back; if it lands unescaped in a rendered error panel
    # it executes. We embed the payload in a GraphQL *string* position inside a
    # field alias comment-like token so the parser surfaces it verbatim.
    marker_a = marker_factory()
    payload_a = _xss_payload(marker_a)
    # Field names can't contain `<`, so the parser raises a syntax error that
    # echoes the raw source fragment — exactly the reflection we want to catch.
    q_a = "query { %s }" % payload_a
    resp_a = _post_json(session, url, {"query": q_a}, timeout, follow_redirects)
    if resp_a is not None:
        body_a = resp_a.text or ""
        ct_a = (resp_a.headers.get("Content-Type", "") or "").lower()
        if _raw_reflected(body_a, payload_a, marker_a):
            is_json = any(j in ct_a for j in _JSON_CT)
            findings.append({
                "url": url,
                "param": "query (error-message)",
                "context": "graphql-error-reflection",
                "source": "graphql",
                # JSON content-type alone won't execute, but error messages are
                # routinely rendered as HTML by GraphQL IDEs / client panels →
                # medium with fp_risk so the v2 gate / verifier can promote.
                "severity": "medium",
                "fp_risk": is_json,
                "fp_reason": (
                    "GraphQL error message reflects the payload unescaped. "
                    "Exploitable when the client renders error messages as HTML "
                    "(GraphiQL / Apollo Sandbox / custom panels). If errors are "
                    "only ever shown as text, impact is reduced — verify how the "
                    "front-end displays GraphQL errors."
                    if is_json else
                    "GraphQL error reflected unescaped in an HTML content-type "
                    "response — directly renderable."),
                "payload": payload_a,
                "content_type": ct_a,
                "evidence": f"payload '{payload_a}' reflected raw in GraphQL "
                            f"error response ({ct_a or 'no content-type'})",
                "cwe_hint": "CWE-79",
                "response_body": body_a,
                "response_headers": dict(resp_a.headers),
            })

    # ── Vector B: string-variable reflection ────────────────────────────────
    # Drive the payload through a typed String variable. If the server echoes
    # variable values (validation errors, debug, or a resolver that reflects the
    # argument) the canary comes back inside `data`/`errors`.
    marker_b = marker_factory()
    payload_b = _xss_payload(marker_b)
    # v10.76 FN fix: the old query declared $q but NEVER used it, so a spec-
    # compliant server rejected it with the NoUnusedVariables rule and echoed only
    # the variable NAME — the payload VALUE never came back and this vector was
    # dead. Feed $q into the standard introspection `__type(name:)` field (typed
    # String! to match), so the variable is actually consumed; a server that
    # reflects input values (in data or verbose errors) now surfaces the canary.
    q_b = "query Probe($q: String!) { __type(name: $q) { name } }"
    resp_b = _post_json(session, url,
                        {"query": q_b, "variables": {"q": payload_b}},
                        timeout, follow_redirects)
    if resp_b is not None:
        body_b = resp_b.text or ""
        ct_b = (resp_b.headers.get("Content-Type", "") or "").lower()
        if _raw_reflected(body_b, payload_b, marker_b):
            is_json = any(j in ct_b for j in _JSON_CT)
            findings.append({
                "url": url,
                "param": "variables.q (String)",
                "context": "graphql-variable-reflection",
                "source": "graphql",
                "severity": "medium",
                "fp_risk": is_json,
                "fp_reason": (
                    "A String variable is reflected unescaped in the GraphQL "
                    "response. Reflected/stored XSS if the client renders this "
                    "value into the DOM (innerHTML). Verify the client sink — a "
                    "value only ever shown via textContent is inert."),
                "payload": payload_b,
                "content_type": ct_b,
                "evidence": f"String variable value '{payload_b}' reflected raw "
                            f"in GraphQL response ({ct_b or 'no content-type'})",
                "cwe_hint": "CWE-79",
                "response_body": body_b,
                "response_headers": dict(resp_b.headers),
            })

    return findings
