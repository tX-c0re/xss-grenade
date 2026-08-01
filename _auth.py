"""Authentication support — cookie injection for authenticated scanning.

THE PROBLEM THIS SOLVES
-----------------------
~80% of real-world XSS bugs hide behind authentication: admin panels,
user profile pages, settings dialogs, ticket systems, internal dashboards.
A scanner that only walks the public surface misses all of them.

This module adds the lowest-friction form of auth: COOKIE INJECTION. The
user logs in manually (browser DevTools → Application → Cookies → copy as
header), pastes the cookie string into the scanner, and the scanner runs
every subsequent request with that session.

WHY THIS IS THE RIGHT FIRST STEP
--------------------------------
- Works for 99% of web apps. PHP sessions, Django sessionid, Rails session,
  JWT-in-cookie, Laravel laravel_session — all of them just need the
  Cookie header preserved.
- Zero protocol-specific code. No CSRF token extraction, no MFA juggling,
  no OAuth dance. The user already logged in via the browser.
- Surprisingly powerful: combined with the scanner's existing crawler,
  it discovers authenticated routes from the moment the session cookie
  is present (because the crawler now gets HTTP 200 instead of 302).

LIMITATIONS BY DESIGN
---------------------
- Session expires mid-scan → no recovery (user must restart). A form-login
  fallback is planned but not in this module.
- CSRF tokens on POST forms: handled separately by the existing
  inject_post_params() — out of scope here.
- Per-request token rotation (some APIs rotate tokens on each call):
  not supported. Would need request-level interception.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ── Cookie parsing ───────────────────────────────────────────────────────────

_COOKIE_PAIR_RE = re.compile(
    r"""
    \s*
    (?P<name>[^=;,\s]+)          # name: no =, ;, comma, whitespace
    \s*=\s*
    (?P<value>"[^"]*"|[^;]*?)    # value: quoted, or until ; (non-greedy)
    \s*
    (?:;|$)
    """,
    re.VERBOSE,
)


def parse_cookie_string(cookie_str: str) -> Dict[str, str]:
    """Parse a Cookie header value into a dict.

    Accepts the format you get when copying from browser DevTools:
        "PHPSESSID=abc123; remember_me=xyz; theme=dark"

    Also accepts the Set-Cookie format (everything after the first ; is
    discarded as attributes — Path, Domain, HttpOnly, etc.).

    Returns {} on empty input. Skips malformed entries silently rather
    than raising — partial parse is better than no auth at all.
    """
    if not cookie_str:
        return {}
    cookies: Dict[str, str] = {}
    # Strip optional "Cookie: " prefix if user pasted the full header line
    s = cookie_str.strip()
    if s.lower().startswith("cookie:"):
        s = s[7:].strip()

    for match in _COOKIE_PAIR_RE.finditer(s):
        name = match.group("name").strip()
        value = match.group("value").strip()
        # Strip surrounding quotes
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        # Skip attributes that sometimes leak from Set-Cookie pastes
        if name.lower() in ("path", "domain", "expires", "max-age",
                             "secure", "httponly", "samesite", "priority"):
            continue
        if not name:
            continue
        cookies[name] = value
    return cookies


def cookies_to_header(cookies: Dict[str, str]) -> str:
    """Inverse of parse_cookie_string — for logging/debugging."""
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


# ── Session injection ────────────────────────────────────────────────────────

def inject_cookies_into_session(session, cookies: Dict[str, str],
                                  domain: Optional[str] = None) -> int:
    """Inject cookies into a requests.Session for all subsequent requests.

    Args:
        session: a requests.Session (or compatible — must have .cookies.set())
        cookies: dict from parse_cookie_string()
        domain: scope the cookies to this host (recommended — prevents the
                cookies from leaking to redirects that go off-host).
                If None, the cookies are global to the session.

    Returns: number of cookies actually injected.
    """
    if not cookies:
        return 0
    count = 0
    for name, value in cookies.items():
        try:
            if domain:
                # Scope explicitly to host — both bare host and ".host"
                # so subdomains inherit. requests merges these correctly.
                session.cookies.set(name, value, domain=domain)
            else:
                session.cookies.set(name, value)
            count += 1
        except Exception as e:
            logger.warning(f"Failed to inject cookie {name}: {e}")
    return count


# ── Session validation ───────────────────────────────────────────────────────
# After injecting cookies, we want to verify the session is actually live.
# We can't always tell — but we can detect the obvious failure modes.

_LOGIN_PAGE_SIGNALS = [
    # Form-level
    re.compile(r'<form[^>]*\baction\s*=\s*["\']?[^"\'>\s]*(?:login|signin|auth)',
                re.IGNORECASE),
    re.compile(r'<input[^>]*\bname\s*=\s*["\']?password\b', re.IGNORECASE),
    re.compile(r'<input[^>]*\btype\s*=\s*["\']?password\b', re.IGNORECASE),
    # Title / heading
    re.compile(r'<title[^>]*>[^<]*(?:log\s*in|sign\s*in|přihlášení|login)',
                re.IGNORECASE),
    re.compile(r'<h\d[^>]*>[^<]*(?:please\s+log\s*in|please\s+sign\s*in)',
                re.IGNORECASE),
    # API responses
    re.compile(r'["\'](?:error|message)["\']\s*:\s*["\'][^"\']*(?:unauthor|not\s+logg|401)',
                re.IGNORECASE),
]

_AUTH_SUCCESS_SIGNALS = [
    # Strong positive signals — when present, almost certainly authenticated
    re.compile(r'\b(?:log\s*out|sign\s*out|odhlásit)\b', re.IGNORECASE),
    re.compile(r'<a[^>]*href\s*=\s*["\']?[^"\'>\s]*(?:logout|sign[-_]?out|signout)',
                re.IGNORECASE),
    re.compile(r'\bMy\s+(?:Account|Profile|Dashboard|Settings)\b', re.IGNORECASE),
]


def looks_like_login_page(body: str, status_code: int,
                          final_url: str = "") -> Tuple[bool, str]:
    """Heuristic: does this response look like 'you got redirected to login'?

    Returns (is_login_page, reason).

    This is INTENTIONALLY conservative — we'd rather miss a login-page
    detection than tell the user "your auth doesn't work" when it does.
    The cost of a false negative here is just the user spending 10 seconds
    sanity-checking; the cost of a false positive is the scanner refusing
    to run with a perfectly good session.
    """
    if status_code == 401:
        return True, "HTTP 401 Unauthorized"
    if status_code == 403:
        # 403 might be auth, might be WAF, might be intentional ACL.
        # Don't flag — let the user decide.
        return False, ""

    # URL-level signal: was the user redirected to /login?
    if final_url:
        path = urlparse(final_url).path.lower()
        if any(seg in path for seg in ("/login", "/signin", "/sign-in",
                                        "/auth/login", "/account/login",
                                        "/users/sign_in")):
            return True, f"redirected to login URL: {final_url}"

    if not body:
        return False, ""

    # Look for explicit success signal first — if we see "Logout" link,
    # we're authenticated regardless of any other signal.
    body_sample = body[:50000]  # first 50KB is enough; avoids huge body scans
    success_hits = sum(1 for rx in _AUTH_SUCCESS_SIGNALS
                        if rx.search(body_sample))
    if success_hits >= 1:
        return False, ""

    # Now look for login-page signals — require ≥2 matches to avoid
    # false-positive on pages that just happen to mention "password"
    login_hits = sum(1 for rx in _LOGIN_PAGE_SIGNALS
                      if rx.search(body_sample))
    if login_hits >= 2:
        return True, f"login form heuristic matched ({login_hits} signals)"

    return False, ""


def validate_session(session, target_url: str,
                      timeout: float = 10.0) -> Dict[str, object]:
    """Probe the target URL with the configured session, decide whether
    the auth is actually working.

    Returns a dict:
      {
        "valid": bool,         # True if session looks authenticated
        "status_code": int,
        "final_url": str,      # URL after redirects
        "reason": str,         # why we decided valid/invalid
        "cookies_sent": int,   # how many cookies the session has for this domain
      }

    'valid: True' doesn't guarantee auth — it just means we couldn't find
    evidence of unauth. 'valid: False' is high-confidence — we have a
    concrete login-page signal.
    """
    try:
        r = session.get(target_url, timeout=timeout,
                        allow_redirects=True)
    except Exception as e:
        return {
            "valid": False,
            "status_code": 0,
            "final_url": "",
            "reason": f"request failed: {type(e).__name__}: {e}",
            "cookies_sent": 0,
        }

    final_url = r.url
    is_login, reason = looks_like_login_page(r.text or "", r.status_code,
                                              final_url)

    # Count cookies in session for this domain.
    # v10.80 fix: use the parsed HOSTNAME (strips the port) and match on host
    # equality or a proper leading-dot suffix, with explicit parentheses. The old
    # `A or B in C or D` mis-parenthesized (precedence) and used substring `in`,
    # so cookie domain "ple.com" counted as belonging to host "example.com".
    parsed = urlparse(target_url)
    _host = (parsed.hostname or parsed.netloc or "").lower()
    cookies_for_host = sum(
        1 for c in session.cookies
        if (not c.domain
            or _host == c.domain.lstrip(".").lower()
            or _host.endswith("." + c.domain.lstrip(".").lower()))
    )

    return {
        "valid": not is_login,
        "status_code": r.status_code,
        "final_url": final_url,
        "reason": reason if is_login
                  else f"OK (HTTP {r.status_code})",
        "cookies_sent": cookies_for_host,
    }


# ── Auth config file (YAML / JSON) ───────────────────────────────────────────
# For CLI use — users can store auth in a config file instead of passing
# secrets on the command line (which leaks into shell history).

def load_auth_config(path: str) -> Dict[str, str]:
    """Load auth config from a YAML or JSON file.

    Expected schema:
      cookies: "PHPSESSID=abc; remember=xyz"
      # OR:
      cookies:
        PHPSESSID: abc
        remember: xyz

    Returns {} on missing/unreadable file. Raises on syntactically invalid
    file — better to fail loudly than scan unauthenticated by accident.
    """
    import os
    if not path or not os.path.exists(path):
        return {}

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # Try JSON first (it's a subset of YAML, faster)
    try:
        import json
        data = json.loads(content)
    except json.JSONDecodeError:
        # Fall back to YAML
        try:
            import yaml  # type: ignore
        except ImportError:
            raise RuntimeError(
                f"Auth config {path} is not valid JSON, and PyYAML is not "
                f"installed. Either fix the JSON or run: pip install pyyaml"
            )
        data = yaml.safe_load(content)

    if not isinstance(data, dict):
        raise ValueError(f"Auth config {path} must be a YAML/JSON mapping")

    cookies_raw = data.get("cookies", "")
    if isinstance(cookies_raw, str):
        return parse_cookie_string(cookies_raw)
    elif isinstance(cookies_raw, dict):
        return {str(k): str(v) for k, v in cookies_raw.items()}
    else:
        return {}


# ── Module info ──────────────────────────────────────────────────────────────

def auth_status_line(cookies: Dict[str, str]) -> str:
    """One-line human-readable summary for logs."""
    if not cookies:
        return "auth: anonymous (no cookies)"
    names = list(cookies.keys())
    if len(names) <= 3:
        return f"auth: {len(cookies)} cookie(s) — {', '.join(names)}"
    return (f"auth: {len(cookies)} cookies — "
            f"{', '.join(names[:3])}, +{len(names)-3} more")
