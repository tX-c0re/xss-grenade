"""
_sourcemap_analyzer.py — JavaScript source-map de-minification (v10.51).

Why this module exists (XSS scanner 2026)
─────────────────────────────────────────
Production front-ends ship a single minified bundle: `a.innerHTML=b(c)`. Static
taint analysis can *see* the `innerHTML` sink but loses the structure that proves
`b(c)` traces to `location.hash` — variable names, function boundaries and the
original control flow are gone. The result is either a missed finding or one too
low-confidence to report.

But most of those bundles ship a **source map** (`//# sourceMappingURL=app.js.map`
or an `X-SourceMap` header). When the map includes `sourcesContent` — which
webpack, Vite, esbuild and Rollup all emit by default — it carries the *original,
unminified source text* for every module. Feeding that readable source back into
the AST taint analyzer recovers exactly the structure minification destroyed:
real names, real functions, real source→sink chains.

This module's single responsibility is source-map mechanics:
  1. find the map (comment, header, or inline `data:` URI),
  2. load + parse it (external fetch or base64 inline),
  3. yield the original `(filename, source_code)` pairs from `sourcesContent`.

It deliberately does NOT run taint analysis itself — the engine pipes each
recovered source straight through the existing `analyze_js_source()` so there is
exactly one taint engine and one reporting path. Dependency-light (json + re +
base64), and every step degrades to "nothing recovered" on malformed input.

Safety / cost notes
────────────────────
- Read-only: a single GET per `.map` file. Caps (`max_sources`, `max_bytes`)
  bound the work so a giant monorepo map can't blow up a scan.
- `node_modules` / vendor chunks are skipped by default: third-party library
  code is the library-CVE phase's job, and de-minifying all of React is noise.
"""
from __future__ import annotations

import base64
import json
import re
from typing import List, Optional, Tuple
from urllib.parse import urljoin


# `//# sourceMappingURL=...` (modern) or the legacy `//@ sourceMappingURL=...`.
# Also matches the `/*# ... */` block-comment form. Last occurrence wins (a
# bundle may contain the directive in a string literal earlier on).
_SM_COMMENT = re.compile(
    r"""[#@]\s*sourceMappingURL\s*=\s*([^\s'"*]+)""",
    re.IGNORECASE,
)

_DATA_URI = re.compile(
    r"""^data:application/json
        (?:;charset=[-\w]+)?
        (?P<b64>;base64)?
        ,(?P<payload>.*)$""",
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

# Vendor / third-party path fragments — de-minifying these is the library-CVE
# phase's concern, not application-code taint. Skipped by default.
_VENDOR_HINTS = (
    "node_modules/", "/vendor/", "bower_components/", "webpack/bootstrap",
    "/runtime", "polyfill", "core-js/", "regenerator-runtime",
)

_DEFAULT_MAX_SOURCES = 60
_DEFAULT_MAX_BYTES = 800_000  # per-source cap; skip enormous generated blobs


def extract_sourcemap_ref(js_body: str,
                          response_headers: Optional[dict] = None
                          ) -> Optional[str]:
    """Return the raw sourceMappingURL reference for a JS bundle, or None.

    Precedence follows the spec: an `X-SourceMap` / `SourceMap` *response header*
    overrides an in-body comment. The returned value is the raw reference
    (relative path, absolute URL, or `data:` URI) — resolve it with
    `resolve_sourcemap_url` against the bundle URL."""
    if response_headers:
        for h in ("SourceMap", "X-SourceMap"):
            # requests' headers are case-insensitive, but accept plain dicts too.
            for k, v in response_headers.items():
                if k.lower() == h.lower() and v:
                    return v.strip()
    if not js_body:
        return None
    matches = _SM_COMMENT.findall(js_body)
    if matches:
        return matches[-1].strip()
    return None


def resolve_sourcemap_url(ref: str, js_url: str) -> str:
    """Resolve a sourceMappingURL reference against the bundle's URL. `data:`
    URIs and absolute URLs pass through unchanged; relative paths are joined."""
    if not ref:
        return ref
    if ref.startswith("data:") or re.match(r"^https?://", ref, re.IGNORECASE):
        return ref
    return urljoin(js_url, ref)


def _parse_inline_data_uri(ref: str) -> Optional[dict]:
    """Decode an inline `data:application/json[;base64],…` source map."""
    m = _DATA_URI.match(ref)
    if not m:
        return None
    payload = m.group("payload")
    try:
        if m.group("b64"):
            raw = base64.b64decode(payload).decode("utf-8", "replace")
        else:
            from urllib.parse import unquote
            raw = unquote(payload)
        return json.loads(raw)
    except Exception:
        return None


def load_sourcemap(session, js_body: str, js_url: str,
                   timeout: float, follow_redirects: bool,
                   response_headers: Optional[dict] = None) -> Optional[dict]:
    """Locate and parse the source map for a JS bundle.

    Handles all three carriers: response header, in-body comment pointing at an
    external `.map`, and inline `data:` URI. Returns the parsed source-map dict
    or None when there is no (usable) map."""
    ref = extract_sourcemap_ref(js_body, response_headers)
    if not ref:
        return None
    resolved = resolve_sourcemap_url(ref, js_url)
    if resolved.startswith("data:"):
        return _parse_inline_data_uri(resolved)
    # External .map fetch (one GET).
    try:
        resp = session.get(resolved, timeout=timeout,
                           allow_redirects=follow_redirects)
    except Exception:
        return None
    if resp is None or resp.status_code >= 400:
        return None
    body = resp.text or ""
    # Some servers prepend `)]}'` (XSSI guard) to maps — strip a leading junk line.
    if body[:4] in (")]}'", ")]}\n"):
        body = body.split("\n", 1)[-1]
    try:
        return json.loads(body)
    except Exception:
        return None


def _is_vendor(name: str) -> bool:
    low = (name or "").lower()
    return any(h in low for h in _VENDOR_HINTS)


def iter_original_sources(sourcemap: dict, *,
                          skip_vendor: bool = True,
                          max_sources: int = _DEFAULT_MAX_SOURCES,
                          max_bytes: int = _DEFAULT_MAX_BYTES
                          ) -> List[Tuple[str, str]]:
    """Yield `(source_name, source_code)` pairs from a parsed source map.

    Only sources with inlined `sourcesContent` can be recovered — a map without
    it carries positions but not original text, so there is nothing to analyze
    and those entries are skipped. Vendor chunks are skipped by default and
    each source is bounded by `max_bytes`."""
    if not isinstance(sourcemap, dict):
        return []
    sources = sourcemap.get("sources") or []
    contents = sourcemap.get("sourcesContent") or []
    root = sourcemap.get("sourceRoot") or ""
    out: List[Tuple[str, str]] = []
    for i, name in enumerate(sources):
        if len(out) >= max_sources:
            break
        if i >= len(contents):
            break
        code = contents[i]
        if not code or not isinstance(code, str):
            continue  # no inlined content for this source — cannot recover text
        full_name = (root.rstrip("/") + "/" + name) if root else name
        full_name = full_name or f"<source {i}>"
        if skip_vendor and _is_vendor(full_name):
            continue
        if len(code) > max_bytes:
            continue
        out.append((full_name, code))
    return out


def deminify_bundle(session, js_body: str, js_url: str,
                    timeout: float, follow_redirects: bool, *,
                    response_headers: Optional[dict] = None,
                    skip_vendor: bool = True,
                    max_sources: int = _DEFAULT_MAX_SOURCES,
                    max_bytes: int = _DEFAULT_MAX_BYTES
                    ) -> List[Tuple[str, str]]:
    """One-call convenience: locate + load the source map for a JS bundle and
    return the recoverable original `(name, code)` sources. Empty list when the
    bundle has no usable map. The engine runs each pair through its existing
    `analyze_js_source()` so source-map findings share the static-JS pipeline."""
    sm = load_sourcemap(session, js_body, js_url, timeout, follow_redirects,
                        response_headers=response_headers)
    if not sm:
        return []
    return iter_original_sources(sm, skip_vendor=skip_vendor,
                                 max_sources=max_sources, max_bytes=max_bytes)
