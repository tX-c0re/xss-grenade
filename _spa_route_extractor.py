"""
_spa_route_extractor.py
========================
SPA route discovery for Angular / React / Vue / Svelte single-page apps.

Background
----------
Modern SPAs hide their entire URL space behind client-side routing:
  - Angular: hash routes like `/#/login`, `/#/administration`
  - React Router (HashRouter): `/#/path`
  - React Router (BrowserRouter): `/path` via history.pushState
  - Vue Router (hash mode): `/#/path`
  - Vue Router (history mode): `/path`

A static HTML crawler sees only the SPA shell (`<div id="app">`) and stops
because there are no <a href> links to follow. The actual routes are buried
in the bundled JavaScript.

This module scans bundled JS for route definition patterns and yields URLs
that can be fed back into the crawler. It is purely heuristic — it parses
strings, not full AST — but precision is high because route patterns are
very distinctive.

Patterns recognized
-------------------
Angular ($routeProvider, RouterModule.forRoot, Routes):
  {path: 'login', component: ...}
  $routeProvider.when("/admin", ...)

React Router:
  <Route path="/login" component={...}/>
  createBrowserRouter([{path: '/login', element: ...}])
  createHashRouter([{path: '/login', element: ...}])

Vue Router:
  routes: [{path: '/login', component: ...}, {path: '/about', ...}]
  router.addRoute({path: '/x', ...})

Svelte (svelte-routing / SvelteKit):
  <Route path="/login" .../>

Public API
----------

    detect_spa_framework(html, js_bundles) -> str | None
        Returns 'angular' / 'react' / 'vue' / 'svelte' / None.

    extract_routes(js_source) -> List[str]
        Returns list of routes discovered in this JS source.

    build_route_urls(target, routes, hash_mode=True) -> List[str]
        Combines target with each route, applying hash mode if SPA uses it.
"""

from __future__ import annotations

import re
import logging
from typing import List, Optional, Set
from urllib.parse import urlparse, urlunparse

log = logging.getLogger("xss_grenade.spa_routes")


# ──────────────────────────────────────────────────────────────────────────────
# FRAMEWORK FINGERPRINTING
# ──────────────────────────────────────────────────────────────────────────────

def detect_spa_framework(html: str = "",
                          js_sources: Optional[List[str]] = None
                          ) -> Optional[str]:
    """Return SPA framework name based on HTML/JS markers, or None.

    Order matters: more specific markers first. A page can superficially
    contain multiple framework names (e.g. comments, dependency lists), so we
    look for *runtime* markers (function calls, attribute names) that imply
    the framework is actually loaded and used.
    """
    js_sources = js_sources or []
    blob = (html or "") + "\n" + "\n".join(js_sources)
    if not blob.strip():
        return None

    # Angular: very distinctive ng* attributes + AngularJS / Angular core symbols
    if (
        '<app-root' in blob
        or 'ng-version=' in blob
        or 'platformBrowserDynamic' in blob
        or 'NgModule' in blob
        or '$routeProvider' in blob
        or 'RouterModule.forRoot' in blob
    ):
        return 'angular'

    # React Router specific functions
    if (
        'createBrowserRouter' in blob
        or 'createHashRouter' in blob
        or 'BrowserRouter' in blob
        or 'HashRouter' in blob
        or 'react-router-dom' in blob
        or '__REACT_DEVTOOLS_GLOBAL_HOOK__' in blob
    ):
        return 'react'

    # Vue / Vue Router
    if (
        'vue-router' in blob
        or 'createRouter' in blob   # Vue 3
        or 'VueRouter' in blob      # Vue 2
        or '__VUE_HMR_RUNTIME__' in blob
        or '__vue_app__' in blob
    ):
        return 'vue'

    # Svelte
    if (
        '__svelte' in blob
        or 'svelte-routing' in blob
        or 'svelte-kit' in blob
        or 'sveltekit' in blob
    ):
        return 'svelte'

    return None


def detect_routing_mode(html: str = "",
                         js_sources: Optional[List[str]] = None,
                         target_url: str = "") -> str:
    """Return 'hash' or 'history' (default 'history').

    Strongest signal: the user-supplied target URL itself. If user typed
    /#/something, hash mode is in use right now regardless of framework.

    Hash mode is the historical default for AngularJS and Vue Router 2; modern
    React Router defaults to history (BrowserRouter) but supports HashRouter.
    """
    # Strongest signal: user navigated to a #/ URL — they ARE using hash mode
    if target_url:
        parsed = urlparse(target_url)
        if parsed.fragment.startswith('/') or parsed.fragment == '':
            if '#/' in target_url:
                return 'hash'
        # Path part is just /, fragment starts with /  → hash routes
        if parsed.path in ('', '/') and parsed.fragment:
            return 'hash'

    js_sources = js_sources or []
    blob = (html or "") + "\n" + "\n".join(js_sources)
    if 'createHashRouter' in blob or 'HashRouter' in blob:
        return 'hash'
    if "mode: 'hash'" in blob or 'mode:"hash"' in blob:
        return 'hash'
    if '$routeProvider' in blob:
        return 'hash'
    if re.search(r'href\s*=\s*["\']\s*[#/]+#/', html or ""):
        return 'hash'
    return 'history'


# ──────────────────────────────────────────────────────────────────────────────
# ROUTE EXTRACTION
# ──────────────────────────────────────────────────────────────────────────────

# Angular: matches {path: 'login', ...}, also path:"login", path: `login`
# Captures Angular Routes config arrays — the most common pattern.
_RE_ANGULAR_ROUTE = re.compile(
    r"""
    \bpath\s*:\s*           # path:
    (['"`])                 # opening quote
    ([^'"`\\]*)             # route value (no quotes/backslashes)
    \1                      # closing quote
    """,
    re.VERBOSE,
)

# AngularJS legacy: $routeProvider.when('/route', ...)
_RE_ANGULARJS_WHEN = re.compile(
    r"""
    \.when\s*\(\s*          # .when(
    (['"])                  # opening quote
    (/[^'"]*)               # route value (must start with /)
    \1                      # closing quote
    """,
    re.VERBOSE,
)

# React Router: <Route path="/login" />
# Note: this is in source code (JSX); production bundles compile JSX away.
_RE_REACT_ROUTE = re.compile(
    r"""
    <Route\b[^>]*?          # opening <Route tag
    \bpath\s*=\s*           # path=
    (?:                     # value: either {"..."} or "..." 
        \{\s*(['"`])([^'"`]+)\1\s*\}
        |
        (['"])([^'"]+)\3
    )
    """,
    re.VERBOSE,
)

# React Router (compiled): { path: "...", element: ... }
# Same as Angular pattern essentially — both use {path: ...}.

# Vue Router (Vue 2 + Vue 3): same {path: '...'} pattern as Angular.

# Generic capture: anything matching {path: '...'} — we can't always tell
# Angular vs Vue vs React from compiled bundle. The pattern is identical.
# So _RE_ANGULAR_ROUTE handles all three.


def extract_routes(js_source: str,
                    framework_hint: Optional[str] = None) -> List[str]:
    """Extract route paths from a single JS source. Returns deduplicated list.

    Args:
        js_source: JavaScript source code (bundle, inline script, or .js file)
        framework_hint: optional ('angular' / 'react' / 'vue' / 'svelte');
                        narrows pattern matching.

    Returns:
        List of route strings (e.g. ['/login', '/admin', '/basket']).
    """
    if not js_source:
        return []

    routes: Set[str] = set()

    # Angular / Vue / React-compiled: {path: '...'}
    for match in _RE_ANGULAR_ROUTE.finditer(js_source):
        route = match.group(2).strip()
        if _is_valid_route(route):
            routes.add(_normalize_route(route))

    # AngularJS legacy: .when('/route', ...)
    for match in _RE_ANGULARJS_WHEN.finditer(js_source):
        route = match.group(2).strip()
        if _is_valid_route(route):
            routes.add(_normalize_route(route))

    # React JSX: <Route path="/login" />
    for match in _RE_REACT_ROUTE.finditer(js_source):
        route = match.group(2) or match.group(4) or ""
        route = route.strip()
        if _is_valid_route(route):
            routes.add(_normalize_route(route))

    return sorted(routes)


def _is_valid_route(route: str) -> bool:
    """Filter out garbage, wildcards, dynamic templates we can't fetch."""
    if not route:
        return False
    if len(route) > 100:                  # absurdly long, probably not a route
        return False
    if route in ('', '/', '*', '**'):      # noise
        return False
    # Ignore catch-all wildcards
    if route.startswith('**'):
        return False
    # Ignore Angular component selectors like 'app-foo' that pattern-match path:
    if not route.startswith('/') and ' ' in route:
        return False
    # Ignore http:// strings caught by accident
    if route.startswith(('http://', 'https://', '//')):
        return False
    # Ignore obvious non-route strings (regex patterns, queries, etc.)
    if any(c in route for c in ('\n', '\t', '<', '>', '"', "'", '`')):
        return False
    return True


def _normalize_route(route: str) -> str:
    """Ensure leading slash, drop trailing slash (except root)."""
    if not route.startswith('/'):
        route = '/' + route
    if len(route) > 1 and route.endswith('/'):
        route = route.rstrip('/')
    return route


# ──────────────────────────────────────────────────────────────────────────────
# URL BUILDING
# ──────────────────────────────────────────────────────────────────────────────

def _substitute_dynamic_params(route: str) -> List[str]:
    """Replace dynamic path params (:id, :slug) with sample values.
    Returns 1+ concrete routes (we can try multiple substitutions)."""
    if ':' not in route:
        return [route]
    # Replace :word with a sample value — '1' for id-style, 'sample' otherwise
    def repl(m):
        name = m.group(1).lower()
        if 'id' in name or 'num' in name:
            return '1'
        return 'sample'
    concrete = re.sub(r':(\w+)', repl, route)
    return [concrete]


def build_route_urls(target: str,
                      routes: List[str],
                      mode: str = 'history') -> List[str]:
    """Combine target host with discovered routes.

    Args:
        target: any URL on the SPA (e.g. http://localhost:3000/#/)
        routes: list of route paths from extract_routes()
        mode: 'history' (path-based) or 'hash' (#/path-based)

    Returns:
        List of fully-qualified URLs to feed to the crawler. Dynamic
        params (:id, :slug) are substituted with concrete sample values.
    """
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    urls: List[str] = []
    seen: Set[str] = set()
    for route in routes:
        if not route.startswith('/'):
            route = '/' + route
        for concrete in _substitute_dynamic_params(route):
            if mode == 'hash':
                url = f"{base}/#{concrete}"
            else:
                url = f"{base}{concrete}"
            if url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def discover_spa_urls(target: str,
                       html: str,
                       js_sources_dict: dict
                       ) -> tuple:
    """One-shot SPA discovery: detect framework, extract routes, build URLs.

    Args:
        target: user-supplied URL
        html: response HTML body for target
        js_sources_dict: {url: source_text} of JS bundles fetched

    Returns:
        (framework, mode, urls) — framework may be None (no SPA detected),
        urls is list of fully-qualified URLs (may be empty).
    """
    js_list = list(js_sources_dict.values())
    framework = detect_spa_framework(html, js_list)
    if framework is None:
        return (None, 'history', [])

    mode = detect_routing_mode(html, js_list, target_url=target)

    # Extract routes from each JS source, deduplicate
    all_routes: Set[str] = set()
    for js_url, js_src in js_sources_dict.items():
        routes = extract_routes(js_src, framework_hint=framework)
        for r in routes:
            all_routes.add(r)

    # Sort for deterministic output, prefer shorter/common routes first
    sorted_routes = sorted(all_routes, key=lambda r: (len(r), r))
    urls = build_route_urls(target, sorted_routes, mode=mode)
    return (framework, mode, urls)


# ──────────────────────────────────────────────────────────────────────────────
# REST API ENDPOINT EXTRACTION (the real attack surface in SPA apps)
# ──────────────────────────────────────────────────────────────────────────────
#
# In any SPA, the bundle contains direct references to backend API endpoints
# that the SPA calls via fetch/axios/$http. Examples from Juice Shop:
#   "/rest/products/search?q=" + query
#   "/api/Feedbacks"
#   "/rest/user/whoami"
#   "/api/Products/" + id
#
# These are REAL HTTP endpoints with real query parameters — far more useful
# for XSS testing than hash routes like /#/login.

# Capture URL-like string literals starting with /api/, /rest/, /v1/, /v2/, etc.
# We're conservative — only common API path prefixes to keep noise down.
_RE_REST_ENDPOINT = re.compile(
    r"""
    (['"`])                       # opening quote
    (
        /                          # absolute path
        (?:api|rest|v\d|graphql|admin/api)  # known API prefix
        /[\w/?=&:.\-]*             # path + maybe query string
    )
    \1                             # closing quote
    """,
    re.VERBOSE,
)


def extract_rest_endpoints(js_source: str) -> List[str]:
    """Return REST API endpoint paths discovered in JS source.

    Captures string literals like:
      "/api/Feedbacks", '/rest/products/search?q=', `/v1/users/${id}`
    """
    if not js_source:
        return []
    endpoints: Set[str] = set()
    for m in _RE_REST_ENDPOINT.finditer(js_source):
        path = m.group(2).strip()
        # Skip endpoints with template-literal interpolation that survived
        # ('${' or template fragments)
        if '${' in path or '`' in path:
            continue
        # Skip absurdly long matches
        if len(path) > 150:
            continue
        # Strip template variable :param to make fetchable URL
        path = re.sub(r':\w+', '1', path)
        # Strip trailing + (string concatenation artifact)
        path = path.rstrip('+').rstrip()
        if not path or path == '/api/' or path == '/rest/':
            continue
        endpoints.add(path)
    return sorted(endpoints)


# ──────────────────────────────────────────────────────────────────────────────
# SPA ROUTE → PARAM HEURISTICS (well-known param names per route)
# ──────────────────────────────────────────────────────────────────────────────
#
# Many SPA routes accept query parameters that are reflected (XSS targets)
# but the static HTML doesn't reveal them. We use route-name heuristics to
# add probe params for common patterns.
_ROUTE_PARAM_HINTS: List[tuple] = [
    # (substring in route, [list of param names to try])
    ('search',           ['q', 'query', 'term']),
    ('track-result',     ['id', 'orderId', 'trackingId']),
    ('track',            ['id']),
    ('redirect',         ['to', 'url', 'next']),
    ('product',          ['id']),
    ('order',            ['id']),
    ('user',             ['id']),
    ('item',             ['id']),
    ('view',             ['id']),
    ('detail',           ['id']),
    ('show',             ['id']),
    ('result',           ['id', 'q']),
    ('callback',         ['code', 'token', 'state']),
    ('auth',             ['token', 'code']),
    ('reset',            ['token']),
    ('verify',           ['token', 'code']),
    ('confirm',          ['token']),
]


def add_param_hints_to_urls(urls: List[str]) -> List[str]:
    """For each URL, if route name suggests likely params, add variants.

    Example: http://x/#/search → http://x/#/search?q=test
             http://x/#/track-result → http://x/#/track-result?id=1
    Returns original URLs PLUS new probe variants. Probe values are harmless
    canary-like tokens that the engine's pre-scan probe will replace.
    """
    out: List[str] = []
    seen: Set[str] = set()
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        out.append(url)
        # Find the path portion (after fragment if hash mode, or after host)
        parsed = urlparse(url)
        # In hash mode the fragment is what matters
        path_to_check = parsed.fragment or parsed.path
        path_lower = path_to_check.lower()
        for substring, params in _ROUTE_PARAM_HINTS:
            if substring in path_lower:
                for pname in params:
                    sep = '&' if '?' in url else '?'
                    new_url = f"{url}{sep}{pname}=test"
                    if new_url not in seen:
                        seen.add(new_url)
                        out.append(new_url)
                break  # One hint per route is enough
    return out


def build_rest_endpoint_urls(target: str, endpoints: List[str]) -> List[str]:
    """Combine target host with REST endpoint paths."""
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    out: List[str] = []
    seen: Set[str] = set()
    for ep in endpoints:
        if not ep.startswith('/'):
            ep = '/' + ep
        url = base + ep
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out
