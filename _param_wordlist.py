"""Parameter wordlist fuzzing — discovers GET parameters that the crawler
can't see because nothing in the HTML links to them.

THE PROBLEM THIS SOLVES
-----------------------
The crawler-based parameter discovery in find_param_urls() only extracts
parameters that appear in the page: <a href="?x=1">, <form>, src=. But PHP
apps read $_GET['attachment'] directly — the parameter works even though
no link to it exists anywhere. A pure crawl-based scanner is structurally
blind to these.

Real example (estrava): the crawler found jidelnicek.php?idzar=10&lang=...
so it tested `lang`. But /estrava/stara/?attachment=... is vulnerable on a
parameter that's never linked — the crawler never sees it, never tests it.

This is the #1 reason a crawl-based scanner reports a false negative where
nuclei's `top-xss-params` template finds a bug.

HOW IT WORKS
------------
1. For each endpoint with NO query params (or few), inject a batch of
   common parameter names from a wordlist, each with a unique canary value.
2. Fetch the response, check which canaries reflect.
3. Reflected param names are real inputs → feed them into the normal
   scan pipeline as if the crawler had found them.

This is detection-only: it finds *which parameters are live*, then the
existing context-aware / fuzzer phases do the actual XSS testing.

COST CONTROL
------------
- Batched: ~25 params per request (not 1 req/param) — keeps it to a
  handful of requests per endpoint.
- Only runs on param-less endpoints by default (the crawler already
  covered the ones with visible params).
- Hard cap on endpoints tested.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs


# ── Parameter wordlist ────────────────────────────────────────────────────────
# Curated from: nuclei top-xss-params, Arjun's db, SecLists param names,
# PortSwigger param miner defaults. Ordered roughly by hit frequency.
# Kept deliberately focused (~220 names) — a 6000-entry list would balloon
# request counts for little marginal gain.
COMMON_PARAMS: List[str] = [
    # ── highest-frequency reflective params ──
    "q", "s", "search", "query", "keyword", "keywords", "term", "text",
    "id", "page", "p", "lang", "language", "locale", "l", "url", "uri",
    "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "returnurl", "next", "dest", "destination", "continue", "goto", "go",
    "callback", "jsonp", "cb", "json_callback", "api_callback",
    "name", "username", "user", "email", "emailto", "to", "from", "subject",
    "message", "msg", "body", "comment", "content", "title", "description",
    "value", "val", "data", "input", "output", "result", "type", "category",
    "categoryid", "cat", "cid", "pid", "uid", "gid", "sid", "tid", "aid",
    # ── pagination / sorting ──
    "offset", "limit", "start", "end", "count", "num", "per_page", "rows",
    "size", "max", "min", "sort", "order", "orderby", "sortby", "dir",
    "asc", "desc", "filter", "filterby", "group", "groupby",
    # ── auth / session / token ──
    "token", "csrf_token", "csrf", "auth", "auth_token", "access_token",
    "api_key", "apikey", "api", "key", "secret", "session", "sessionid",
    "sid", "hash", "sig", "signature", "nonce", "state", "code",
    "password", "passwd", "pass", "pwd", "otp", "pin", "verify",
    "unsubscribe_token", "reset_token", "confirm_token", "activation",
    # ── file / path / attachment ──
    "file", "filename", "filepath", "path", "dir", "folder", "doc",
    "document", "attachment", "download", "upload", "img", "image",
    "immagine", "photo", "picture", "avatar", "icon", "logo", "media",
    "src", "source", "ref", "referer", "referrer", "origin",
    # ── date / time ──
    "date", "begindate", "enddate", "startdate", "start_date", "end_date",
    "from_date", "to_date", "year", "month", "day", "week", "time",
    "timestamp", "timeout", "duration", "period", "range",
    # ── db / internal (estrava-style) ──
    "db", "dbname", "db_name", "database", "table", "tablename", "column",
    "field", "fieldname", "row", "record", "entry", "item", "items",
    "ids", "list", "list_type", "view", "mode", "action", "act", "do",
    "op", "operation", "func", "function", "method", "cmd", "command",
    "parent", "parent_id", "parentid", "child", "node", "tree", "level",
    "depth", "index", "idx", "pos", "position", "slot", "step", "stage",
    # ── display / UI ──
    "format", "fmt", "output", "render", "template", "tpl", "theme",
    "skin", "style", "css", "layout", "display", "show", "hide", "visible",
    "tab", "section", "module", "component", "widget", "block", "part",
    "width", "w", "height", "h", "color", "bg", "background", "font",
    # ── plugin / provider / status (estrava-style) ──
    "plugin", "plugin_status", "provider", "service", "app", "application",
    "status", "state", "flag", "enabled", "active", "visible", "public",
    "version", "ver", "v", "build", "release", "env", "environment",
    # ── misc commonly-vulnerable ──
    "fid", "kid", "rid", "wid", "eid", "oid", "mid", "nid", "bid",
    "page_id", "post_id", "article_id", "news_id", "event_id", "product_id",
    "terms", "agree", "accept", "confirm", "submit", "save", "update",
    "delete", "remove", "add", "create", "edit", "new", "old", "prev",
    "title", "alt", "label", "caption", "tooltip", "placeholder", "hint",
    "error", "err", "warning", "warn", "notice", "info", "debug", "test",
    "preview", "draft", "live", "cache", "nocache", "force", "reload",
    "json", "xml", "rss", "feed", "ajax", "async", "partial", "raw",
    "country", "city", "region", "zip", "postal", "address", "location",
    "phone", "tel", "mobile", "fax", "company", "org", "department",
    # ── link / nav params (commonly reflected) ──
    "link", "links", "href", "anchor", "target", "window", "frame",
    "iframe", "embed", "popup", "modal", "overlay", "menu", "nav",
    "breadcrumb", "crumb", "back", "forward", "home", "exit", "logout",
    "login", "signin", "signup", "register", "account", "profile",
]

# Deduplicate while preserving order
_seen: Set[str] = set()
COMMON_PARAMS = [p for p in COMMON_PARAMS if not (p in _seen or _seen.add(p))]


# ── Canary tokens ─────────────────────────────────────────────────────────────
# Each probed parameter gets a unique alphanumeric canary. We look for the
# canary verbatim in the response — if present, the parameter is reflected.
# Format: pwlNNNN (param-wordlist + index). Alphanumeric only so it survives
# most encoding without mangling, and is greppable.
def _canary_for(index: int) -> str:
    return f"pwl{index:04d}xq"


_CANARY_RE = re.compile(r"pwl(\d{4})xq")


# ── Target-derived parameter names ────────────────────────────────────────────
# A generic wordlist is a guess. The application's OWN code names the inputs it
# actually reads, and those names beat any wordlist because they are guaranteed
# live. Mine them from the target's HTML + inline/linked JS and probe them
# FIRST. This is the piece Katana-style crawlers do not do: they discover URLs,
# not the parameter surface hidden inside client code.
#
# Sources mined:
#   getParam('x') / searchParams.get('x') / URLSearchParams .get('x')
#   params['x'] / query.x / req.query.x            (server + client idioms)
#   <input name=x> / <select name=x> / <textarea name=x>
#   data-param="x" and the literal `?x=` / `&x=` inside strings
_PARAM_NAME_RX = [
    re.compile(r"""\.get\(\s*['"]([A-Za-z_][\w.\-]{0,39})['"]"""),
    re.compile(r"""(?:getParameter|getParam|param|getQuery)\(\s*['"]([A-Za-z_][\w.\-]{0,39})['"]""", re.I),
    re.compile(r"""\b(?:params|query|args|GET|POST|REQUEST)\s*\[\s*['"]([A-Za-z_][\w.\-]{0,39})['"]\s*\]"""),
    re.compile(r"""\b(?:req\.)?query\.([A-Za-z_]\w{0,39})\b"""),
    re.compile(r"""<(?:input|select|textarea|button)\b[^>]*\bname\s*=\s*['"]?([A-Za-z_][\w.\-]{0,39})""", re.I),
    re.compile(r"""[?&]([A-Za-z_][\w.\-]{0,39})="""),
]

# Names that are almost never a real injectable input — drop to cut noise.
_PARAM_NAME_STOP = {
    "type", "class", "id", "style", "name", "value", "content", "charset",
    "width", "height", "rel", "href", "src", "method", "action", "target",
    "true", "false", "null", "function", "return", "var", "let", "const",
}


def extract_param_names(text: str, max_names: int = 60) -> List[str]:
    """Mine likely GET/POST parameter names out of a page's HTML/JS.

    Precision over recall: single letters, pure numbers, and obvious non-inputs
    are dropped. Returns names in first-seen order (the ones the page mentions
    earliest tend to be the real inputs), de-duplicated.
    """
    if not text:
        return []
    out: List[str] = []
    seen: Set[str] = set()
    for rx in _PARAM_NAME_RX:
        for m in rx.finditer(text):
            nm = m.group(1)
            low = nm.lower()
            if (len(nm) < 2 or low in _PARAM_NAME_STOP or nm.isdigit()
                    or nm in seen):
                continue
            seen.add(nm)
            out.append(nm)
            if len(out) >= max_names:
                return out
    return out


# ── Endpoint selection ────────────────────────────────────────────────────────

def endpoint_needs_wordlist(url: str, existing_param_count: int,
                            min_existing: int = 1) -> bool:
    """Decide whether an endpoint is worth wordlist-probing.

    By default we probe endpoints that have FEWER than min_existing query
    params already — the crawler covered the well-linked ones, the value
    here is finding the hidden inputs on endpoints that look "empty".

    A param-less endpoint like /estrava/stara/ is the prime target.
    """
    return existing_param_count < min_existing


# ── Probe URL construction ────────────────────────────────────────────────────

def build_probe_urls(base_url: str, batch_size: int = 25,
                     extra_params: Optional[List[str]] = None) -> List[Tuple[str, Dict[str, str]]]:
    """Build batched probe URLs for a base endpoint.

    Returns a list of (probe_url, {param_name: canary}) tuples. Each probe
    URL appends `batch_size` wordlist parameters, each set to its unique
    canary value. Batching keeps the request count low: 220 params / 25
    per batch ≈ 9 requests per endpoint.

    The base_url's existing query params (if any) are preserved.
    """
    if not base_url:
        return []
    p = urlparse(base_url)
    if p.scheme not in ("http", "https"):
        return []

    existing = parse_qs(p.query, keep_blank_values=True)
    existing_flat = {k: v[0] if v else "" for k, v in existing.items()}

    # v10.87: names mined from the target itself go FIRST, ahead of the generic
    # wordlist — they are the inputs the application demonstrably reads, so the
    # early batches carry by far the highest hit rate. max_batches then truncates
    # the generic tail rather than the good candidates.
    _names = list(COMMON_PARAMS)
    if extra_params:
        _seen_x = set()
        head = []
        for nm in extra_params:
            if nm and nm not in _seen_x:
                _seen_x.add(nm)
                head.append(nm)
        _names = head + [p for p in COMMON_PARAMS if p not in _seen_x]

    probes: List[Tuple[str, Dict[str, str]]] = []
    for batch_start in range(0, len(_names), batch_size):
        batch = _names[batch_start:batch_start + batch_size]
        canary_map: Dict[str, str] = {}
        query_params = dict(existing_flat)
        for offset, pname in enumerate(batch):
            # Skip a wordlist param if the endpoint already has it (crawler
            # found it → existing pipeline tests it).
            if pname in existing_flat:
                continue
            idx = batch_start + offset
            canary = _canary_for(idx)
            canary_map[pname] = canary
            query_params[pname] = canary
        if not canary_map:
            continue
        probe_url = urlunparse(p._replace(query=urlencode(query_params),
                                          fragment=""))
        probes.append((probe_url, canary_map))
    return probes


# ── Response analysis ─────────────────────────────────────────────────────────

def find_reflected_params(response_body: str,
                          canary_map: Dict[str, str]) -> List[str]:
    """Given a probe response, return the parameter names whose canary
    reflected in the body.

    A reflected canary means the parameter is a live input the server
    echoes back — exactly the kind of parameter that's XSS-testable.
    Reflection alone isn't XSS (the value may be encoded), but it tells
    the scanner *this parameter is worth testing*.
    """
    if not response_body:
        return []
    reflected: List[str] = []
    for pname, canary in canary_map.items():
        if canary in response_body:
            reflected.append(pname)
    return reflected


def build_param_url(base_url: str, reflected_params: List[str],
                    placeholder: str = "1") -> Optional[str]:
    """Construct a URL with the reflected parameters attached, ready to
    hand off to the normal scan pipeline (find_param_urls-compatible).

    Each reflected param gets a harmless placeholder value. The scan
    pipeline will then substitute payloads for each one.
    """
    if not base_url or not reflected_params:
        return None
    p = urlparse(base_url)
    if p.scheme not in ("http", "https"):
        return None
    existing = parse_qs(p.query, keep_blank_values=True)
    query = {k: v[0] if v else "" for k, v in existing.items()}
    for pname in reflected_params:
        if pname not in query:
            query[pname] = placeholder
    return urlunparse(p._replace(query=urlencode(query), fragment=""))


# ── Full workflow ─────────────────────────────────────────────────────────────

def discover_params_for_endpoint(base_url: str,
                                  fetch_fn,
                                  batch_size: int = 25,
                                  max_batches: int = 12,
                                  extra_params: Optional[List[str]] = None) -> Dict:
    """Full parameter-discovery workflow for one endpoint.

    Args:
        base_url: the endpoint to probe (e.g. https://x.com/estrava/stara/)
        fetch_fn: callable(url) -> response_body str (or None on error).
                  The caller supplies this so we reuse their session,
                  proxy, Tor, UA rotation, etc.
        batch_size: wordlist params per request.
        max_batches: hard cap on requests per endpoint.

    Returns a dict:
      {
        "base_url": str,
        "reflected_params": [str, ...],   # param names that echoed back
        "param_url": str | None,           # URL with reflected params attached
        "batches_sent": int,
        "params_probed": int,
      }
    """
    probes = build_probe_urls(base_url, batch_size=batch_size,
                              extra_params=extra_params)
    probes = probes[:max_batches]

    all_reflected: List[str] = []
    params_probed = 0
    batches_sent = 0

    for probe_url, canary_map in probes:
        params_probed += len(canary_map)
        batches_sent += 1
        try:
            body = fetch_fn(probe_url)
        except Exception:
            body = None
        if not body:
            continue
        reflected = find_reflected_params(body, canary_map)
        all_reflected.extend(reflected)

    # Dedup, preserve order
    seen: Set[str] = set()
    all_reflected = [p for p in all_reflected
                     if not (p in seen or seen.add(p))]

    return {
        "base_url": base_url,
        "reflected_params": all_reflected,
        "param_url": build_param_url(base_url, all_reflected),
        "batches_sent": batches_sent,
        "params_probed": params_probed,
    }


# ── Stats helpers ─────────────────────────────────────────────────────────────

def wordlist_size() -> int:
    """Number of parameter names in the wordlist."""
    return len(COMMON_PARAMS)


def estimate_requests(endpoint_count: int, batch_size: int = 25) -> int:
    """Estimate total request count for N endpoints."""
    batches_per_endpoint = (len(COMMON_PARAMS) + batch_size - 1) // batch_size
    return endpoint_count * batches_per_endpoint
