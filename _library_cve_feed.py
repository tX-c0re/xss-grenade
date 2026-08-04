"""JS library CVE feed — version-based vulnerability matching for common
front-end libraries (jQuery, lodash, Bootstrap, Angular, etc.).

Companion to _dompurify_cve_feed.py. Where that module handles DOMPurify
specifically (it's a sanitizer, so its CVEs gate the PP→XSS chains), this
module covers the broader supply-chain audit: when the scanner detects a
known library by filename + version, it surfaces ALL matching CVEs.

This is detection-only / informational — it doesn't actively exploit. It
turns "you're running jquery-1.11.3.min.js" into "you're running
jquery-1.11.3.min.js → CVE-2015-9251, CVE-2019-11358, CVE-2020-11022,
CVE-2020-11023, CVE-2020-7656".

Data sourced from (verified Jan 2026):
  - NVD (nvd.nist.gov)
  - GitHub Security Advisory Database
  - Snyk vulnerability DB
  - CISA KEV catalog (for exploited-in-wild flag)

Update strategy: quarterly review of GitHub advisories for each tracked
library. Each new CVE = one data entry, no code changes.
"""

import re
from typing import Dict, List, Optional, Tuple


# ── Library identification patterns ───────────────────────────────────────────
# Maps a normalized library name to regexes that match its filename.
# Detection: filename (from URL or path) is matched, then version extracted.
_LIBRARY_FILENAME_PATTERNS: Dict[str, List[re.Pattern]] = {
    "jquery": [
        re.compile(r"jquery[-.]?(\d+\.\d+\.\d+)", re.IGNORECASE),
        re.compile(r"jquery(?:\.min)?\.js", re.IGNORECASE),  # version-less
    ],
    "lodash": [
        re.compile(r"lodash[-.]?(\d+\.\d+\.\d+)", re.IGNORECASE),
        re.compile(r"lodash(?:\.min)?\.js", re.IGNORECASE),
    ],
    "bootstrap": [
        re.compile(r"bootstrap[-.]?(\d+\.\d+\.\d+)", re.IGNORECASE),
        re.compile(r"bootstrap(?:\.min)?\.js", re.IGNORECASE),
    ],
    "angular": [
        # AngularJS (1.x) — note: distinct from Angular 2+
        re.compile(r"angular[-.]?(\d+\.\d+\.\d+)", re.IGNORECASE),
        re.compile(r"angular(?:\.min)?\.js", re.IGNORECASE),
    ],
    # v10.16: moderní frameworky
    "react": [
        re.compile(r"react(?:-dom)?[-.@](\d+\.\d+\.\d+)", re.IGNORECASE),
        # react.js / react-dom.production.min.js / react-dom-client.production.js
        # / react-dom-server.browser.production.js — libovolný -suffix mezi
        # react[-dom] a koncovkou.
        re.compile(r"react(?:-dom)?(?:[-.][a-z.]+)?(?:\.min)?\.js",
                   re.IGNORECASE),
    ],
    # v10.16: React Router (CVE-2026-22029 XSS via open redirect)
    "react-router": [
        re.compile(r"react-router(?:-dom)?[-.@](\d+\.\d+\.\d+)", re.IGNORECASE),
        re.compile(r"react-router(?:-dom)?(?:[-.][a-z.]+)?(?:\.min)?\.js",
                   re.IGNORECASE),
        re.compile(r"@remix-run[/-]router[-.@](\d+\.\d+\.\d+)", re.IGNORECASE),
    ],
    "vue": [
        re.compile(r"vue[-.@](\d+\.\d+\.\d+)", re.IGNORECASE),
        re.compile(r"vue(?:\.runtime)?(?:\.global|\.esm)?(?:\.prod)?(?:\.min)?\.js",
                   re.IGNORECASE),
    ],
    "next": [
        re.compile(r"next[-.@](\d+\.\d+\.\d+)", re.IGNORECASE),
        # Next.js chunky: _next/static/chunks/... (verze často jen v banneru)
        re.compile(r"_next/static/", re.IGNORECASE),
    ],
    "angular-modern": [
        # Angular 2+ bundles: main.<hash>.js, polyfills; verze v banneru
        re.compile(r"@angular[/-]core[-.@](\d+\.\d+\.\d+)", re.IGNORECASE),
    ],
}

# Version extraction from inside source code (when filename has no version).
# Each library exposes its version differently.
_LIBRARY_SOURCE_VERSION_PATTERNS: Dict[str, List[re.Pattern]] = {
    "jquery": [
        # jQuery: `jquery:"3.4.1"` or `jQuery.fn.jquery = "3.4.1"`
        re.compile(r'jquery\s*[:=]\s*["\'](\d+\.\d+\.\d+)["\']', re.IGNORECASE),
    ],
    "lodash": [
        # lodash: `VERSION = '4.17.20'`
        re.compile(r'VERSION\s*=\s*["\'](\d+\.\d+\.\d+)["\']'),
    ],
    "bootstrap": [
        # Bootstrap: `VERSION = '4.3.1'` or `Bootstrap's JavaScript requires`
        re.compile(r'VERSION\s*[:=]\s*["\'](\d+\.\d+\.\d+)["\']'),
    ],
    "angular": [
        # AngularJS: `full:"1.7.9"` inside angular.version object
        re.compile(r'full\s*:\s*["\'](\d+\.\d+\.\d+)["\']'),
    ],
    # v10.16: moderní frameworky — verze v runtime bundlu
    "react": [
        # Reálné minifikované bundly: `c.version="18.2.0"` (react core),
        # `reconcilerVersion:"18.2.0"` / `version:"18.2.0-next-..."` (react-dom).
        # Nevyžaduj uzavírací uvozovku hned za X.Y.Z (může následovat -next-…).
        re.compile(r'(?:react)?version\s*[:=]\s*["\'](\d+\.\d+\.\d+)',
                   re.IGNORECASE),
        re.compile(r'\.version\s*=\s*["\'](\d+\.\d+\.\d+)'),
    ],
    "react-router": [
        # react-router bundle: `version:"7.5.0"` / `.version="7.5.0"`
        re.compile(r'(?:router)?version\s*[:=]\s*["\'](\d+\.\d+\.\d+)',
                   re.IGNORECASE),
        re.compile(r'\.version\s*=\s*["\'](\d+\.\d+\.\d+)'),
    ],
    "vue": [
        # Vue 2: `Cn.version="2.6.14"` (minifikováno). Vue 3 prod string
        # většinou nemá — detekce přes filename/HTML. Suffix-tolerant.
        re.compile(r'(?:vue)?version\s*[:=]\s*["\'](\d+\.\d+\.\d+)',
                   re.IGNORECASE),
        re.compile(r'\.version\s*=\s*["\'](\d+\.\d+\.\d+)'),
    ],
    "next": [
        # Next.js: `"next":"15.1.0"` v buildManifest / __NEXT_DATA__
        re.compile(r'(?:next|version)["\']?\s*[:=]\s*["\'](\d+\.\d+\.\d+)["\']',
                   re.IGNORECASE),
    ],
    "angular-modern": [
        # Angular 2+: `VERSION = {full:"17.3.0"}` / `ng-version="17.3.0"`
        re.compile(r'ng-version=["\'](\d+\.\d+\.\d+)["\']'),
        re.compile(r'VERSION\s*=\s*\{[^}]*full\s*:\s*["\'](\d+\.\d+\.\d+)["\']'),
    ],
}


# ── CVE feed entries ──────────────────────────────────────────────────────────
# Each entry: library, cve, min_version (inclusive, None=any), max_version
# (exclusive = first patched), severity, vector, description, reference.
#
# IMPORTANT: max_version is the FIRST PATCHED version. So "< 3.4.0" means
# max_version="3.4.0" — versions up to but not including 3.4.0 are vulnerable.

LIBRARY_CVE_FEED: List[Dict] = [
    # ════════════════ jQuery ════════════════
    {
        "library": "jquery",
        "cve": "CVE-2015-9251",
        "min_version": None,        # all versions before 3.0.0
        "max_version": "3.0.0",
        "severity": "medium",
        "vector": "xss-cross-domain-ajax",
        "description": (
            "XSS via cross-domain Ajax request without dataType option — "
            "text/javascript responses get executed"
        ),
        "reference": "https://github.com/advisories/GHSA-rmxg-73gg-4mjj",
        "exploited_in_wild": False,
    },
    {
        "library": "jquery",
        "cve": "CVE-2019-11358",
        "min_version": None,        # all versions before 3.4.0
        "max_version": "3.4.0",
        "severity": "medium",
        "vector": "prototype-pollution",
        "description": (
            "Prototype Pollution via jQuery.extend(true, {}, ...) — "
            "enumerable __proto__ property extends Object.prototype"
        ),
        "reference": "https://github.com/advisories/GHSA-6c3j-c64m-qhgq",
        "exploited_in_wild": True,   # part of CISA KEV (Jan 2025)
    },
    {
        "library": "jquery",
        "cve": "CVE-2020-11022",
        "min_version": "1.2.0",
        "max_version": "3.5.0",
        "severity": "medium",
        "vector": "xss-html-manipulation",
        "description": (
            "XSS — passing HTML from untrusted sources to DOM manipulation "
            "methods (.html/.append/etc.) may execute untrusted code"
        ),
        "reference": "https://github.com/advisories/GHSA-gxr4-xjj5-5px2",
        "exploited_in_wild": False,
    },
    {
        "library": "jquery",
        "cve": "CVE-2020-11023",
        "min_version": "1.0.3",
        "max_version": "3.5.0",
        "severity": "medium",
        "vector": "xss-option-elements",
        "description": (
            "XSS — passing HTML containing <option> elements from untrusted "
            "sources to jQuery DOM methods may execute code (CISA KEV)"
        ),
        "reference": "https://github.com/advisories/GHSA-jpcq-cgw6-v4j6",
        "exploited_in_wild": True,   # CISA KEV (Jan 2025), linked to APT
    },
    {
        "library": "jquery",
        "cve": "CVE-2020-7656",
        "min_version": None,
        "max_version": "1.9.0",
        "severity": "medium",
        "vector": "xss-script-injection",
        "description": (
            "XSS — jQuery before 1.9.0 executes inline <script> when loading "
            "HTML via .load() or similar, even after sanitization attempts"
        ),
        "reference": "https://github.com/advisories/GHSA-q4m3-2j7h-f7xw",
        "exploited_in_wild": False,
    },

    # ════════════════ lodash ════════════════
    {
        "library": "lodash",
        "cve": "CVE-2018-3721",
        "min_version": None,
        "max_version": "4.17.5",
        "severity": "medium",
        "vector": "prototype-pollution",
        "description": (
            "Prototype Pollution in defaultsDeep / merge / mergeWith — "
            "modification of Object.prototype via __proto__"
        ),
        "reference": "https://github.com/advisories/GHSA-fvqr-27wr-82fm",
        "exploited_in_wild": False,
    },
    {
        "library": "lodash",
        "cve": "CVE-2018-16487",
        "min_version": None,
        "max_version": "4.17.11",
        "severity": "high",
        "vector": "prototype-pollution",
        "description": (
            "Prototype Pollution in merge / mergeWith / defaultsDeep — "
            "tricked into adding/modifying Object.prototype properties"
        ),
        "reference": "https://github.com/advisories/GHSA-4xc9-xhrj-v574",
        "exploited_in_wild": False,
    },
    {
        "library": "lodash",
        "cve": "CVE-2019-10744",
        "min_version": None,
        "max_version": "4.17.12",
        "severity": "critical",
        "vector": "prototype-pollution",
        "description": (
            "Prototype Pollution in defaultsDeep — constructor payload "
            "injects properties onto Object.prototype (CVSS 9.1)"
        ),
        "reference": "https://github.com/advisories/GHSA-jf85-cpcp-j695",
        "exploited_in_wild": False,
    },
    {
        "library": "lodash",
        "cve": "CVE-2020-8203",
        "min_version": None,
        "max_version": "4.17.20",
        "severity": "high",
        "vector": "prototype-pollution",
        "description": (
            "Prototype Pollution in zipObjectDeep — attacker injects "
            "properties onto Object.prototype (CVSS 7.4)"
        ),
        "reference": "https://github.com/advisories/GHSA-p6mc-m468-83gw",
        "exploited_in_wild": False,
    },
    {
        "library": "lodash",
        "cve": "CVE-2021-23337",
        "min_version": None,
        "max_version": "4.17.21",
        "severity": "high",
        "vector": "command-injection",
        "description": (
            "Command injection in _.template — crafted template option "
            "flows into Function() constructor sink"
        ),
        "reference": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
        "exploited_in_wild": False,
    },

    # ════════════════ Bootstrap ════════════════
    {
        "library": "bootstrap",
        "cve": "CVE-2016-10735",
        "min_version": None,
        "max_version": "3.4.0",
        "severity": "medium",
        "vector": "xss-data-target",
        "description": (
            "XSS in data-target attribute — improper sanitization allows "
            "arbitrary JavaScript via crafted data attribute"
        ),
        "reference": "https://github.com/advisories/GHSA-4p24-vmcr-4gqj",
        "exploited_in_wild": False,
    },
    {
        "library": "bootstrap",
        "cve": "CVE-2018-20676",
        "min_version": None,
        "max_version": "3.4.0",
        "severity": "medium",
        "vector": "xss-data-viewport",
        "description": (
            "XSS in tooltip data-viewport attribute — lacks input sanitization"
        ),
        "reference": "https://github.com/advisories/GHSA-3wqf-4x89-9g79",
        "exploited_in_wild": False,
    },
    {
        "library": "bootstrap",
        "cve": "CVE-2018-20677",
        "min_version": None,
        "max_version": "3.4.0",
        "severity": "medium",
        "vector": "xss-affix-target",
        "description": (
            "XSS in affix configuration target property — improper sanitization"
        ),
        "reference": "https://github.com/advisories/GHSA-ph58-4vrj-w6hr",
        "exploited_in_wild": False,
    },
    {
        "library": "bootstrap",
        "cve": "CVE-2019-8331",
        "min_version": None,
        # NOTE: affects <3.4.1 AND 4.0.0-4.3.0. We model the 3.x range here;
        # the 4.x range is a separate entry below (semver can't express both).
        "max_version": "3.4.1",
        "severity": "medium",
        "vector": "xss-data-template",
        "description": (
            "XSS in tooltip/popover data-template attribute — lacks proper "
            "HTML sanitization (Bootstrap 3.x branch)"
        ),
        "reference": "https://github.com/advisories/GHSA-9v3m-8fp8-mj99",
        "exploited_in_wild": False,
    },
    {
        "library": "bootstrap",
        "cve": "CVE-2019-8331",
        "min_version": "4.0.0",
        "max_version": "4.3.1",
        "severity": "medium",
        "vector": "xss-data-template",
        "description": (
            "XSS in tooltip/popover data-template attribute — lacks proper "
            "HTML sanitization (Bootstrap 4.x branch)"
        ),
        "reference": "https://github.com/advisories/GHSA-9v3m-8fp8-mj99",
        "exploited_in_wild": False,
    },

    # ════════════════ AngularJS (1.x) ════════════════
    {
        "library": "angular",
        "cve": "CVE-2024-8372",
        "min_version": None,
        "max_version": "1.8.3",
        "severity": "medium",
        "vector": "xss-sanitization-bypass",
        "description": (
            "AngularJS sanitization bypass — improper sanitization of "
            "SVG/MathML allows XSS (AngularJS is End-of-Life, no fix)"
        ),
        "reference": "https://github.com/advisories/GHSA-2vrf-hf26-jrp5",
        "exploited_in_wild": False,
    },

    # ════════════════ React (v10.16, ověřeno přes web 2026-05) ════════════════
    {
        "library": "react",
        "cve": "CVE-2025-55182",
        # React2Shell — RCE přes React Server Components Flight protokol.
        # Zranitelné: react-server-dom-* 19.0/19.1.0/19.1.1/19.2.0.
        # Patched: 19.0.1, 19.1.2, 19.2.1. CVSS 10.0, exploitováno ve wild.
        "min_version": "19.0.0",
        "max_version": "19.2.1",
        "severity": "critical",
        "vector": "rce-rsc-deserialization",
        "description": (
            "React2Shell — unauthenticated RCE via unsafe deserialization in "
            "React Server Components 'Flight' protocol (react-server-dom-*). "
            "Single crafted HTTP request → code exec. Affects Next.js, "
            "react-router, Waku, @parcel/rsc, @vitejs/plugin-rsc. CVSS 10.0."
        ),
        "reference": "https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components",
        "exploited_in_wild": True,
    },

    # ════════════════ React Router (v10.16, ověřeno přes web 2026-05) ════════════════
    {
        "library": "react-router",
        "cve": "CVE-2026-22029",
        # XSS přes open redirect — loader/action vrátí redirect na
        # nebezpečnou URL (javascript:) ve Framework/Data/RSC módu.
        # Zranitelné: react-router 7.0.0–7.11.0, @remix-run/router < 1.23.2.
        "min_version": "7.0.0",
        "max_version": "7.11.1",   # patched 7.11.1 / @remix-run/router 1.23.2
        "severity": "high",
        "vector": "xss-open-redirect",
        "description": (
            "XSS via open redirect — in Framework/Data/RSC mode, navigation "
            "redirects from loaders/actions can produce unsafe URLs "
            "(javascript:) that execute on the client. Affects react-router "
            "7.0.0–7.11.0 and @remix-run/router < 1.23.2. Validate redirect "
            "targets / block non-http(s) schemes."
        ),
        "reference": "https://github.com/remix-run/react-router/security/advisories/GHSA-43vp-m6cx-mxc8",
        "exploited_in_wild": False,
    },

    # ════════════════ Next.js (v10.16, ověřeno přes web 2026-05) ════════════════
    {
        "library": "next",
        "cve": "CVE-2025-29927",
        # Middleware authorization bypass přes x-middleware-subrequest header.
        # Patched: 12.3.5, 13.5.9, 14.2.25, 15.2.3.
        "min_version": None,
        "max_version": "15.2.3",
        "severity": "critical",
        "vector": "auth-bypass-middleware",
        "description": (
            "Authorization bypass — spoofing the internal "
            "x-middleware-subrequest header skips Next.js middleware "
            "(auth/authz checks). Patched: 12.3.5/13.5.9/14.2.25/15.2.3. "
            "Note: version banner alone ≠ exploitable (needs middleware-based "
            "authz). CVSS critical, public PoC."
        ),
        "reference": "https://nextjs.org/blog/cve-2025-29927",
        "exploited_in_wild": True,
    },
    {
        "library": "next",
        "cve": "CVE-2025-66478",
        # Next.js side of React2Shell (RCE via React Flight protocol).
        "min_version": "13.0.0",
        "max_version": "15.5.7",   # upgrade na nejnovější patched release
        "severity": "critical",
        "vector": "rce-rsc-deserialization",
        "description": (
            "Next.js RCE via React Flight protocol (companion to React "
            "CVE-2025-55182 / React2Shell) — App Router with affected "
            "react-server-dom-* bundles. Upgrade to latest patched Next.js."
        ),
        "reference": "https://github.com/vercel/next.js/security/advisories/GHSA-9qr9-h5gf-34mp",
        "exploited_in_wild": True,
    },

    # ════════════════ Angular 2+ (v10.16, ověřeno přes web 2026-05) ════════════════
    {
        "library": "angular-modern",
        "cve": "CVE-2025-66412",
        # Stored XSS přes SVG/MathML atributy — neúplné security schema
        # v template compileru. Patched: 19.2.17, 20.3.15, 21.0.2.
        "min_version": None,
        "max_version": "19.2.17",   # nejnižší patched v 19.x větvi
        "severity": "high",
        "vector": "xss-sanitization-bypass",
        "description": (
            "Stored XSS — Angular template compiler's incomplete security "
            "schema lets SVG/MathML URL attributes (xlink:href, math|href) and "
            "SVG animation attributeName bypass sanitization → javascript: "
            "URLs execute. Patched: 19.2.17 / 20.3.15 / 21.0.2. CVSS 8.5."
        ),
        "reference": "https://github.com/advisories/GHSA-v4hv-rgfq-gp49",
        "exploited_in_wild": False,
    },
    {
        "library": "angular-modern",
        "cve": "CVE-2026-32635",
        # XSS přes i18n attribute bindings. Affects v17 – v22 pre-release.
        "min_version": "17.0.0",
        "max_version": "22.0.0",
        "severity": "high",
        "vector": "xss-i18n-binding",
        "description": (
            "XSS via improper handling of i18n attribute bindings — "
            "localization feature interaction bypasses DomSanitizer. "
            "Affects Angular v17–v22. Mitigate with explicit "
            "DomSanitizer + SecurityContext.URL."
        ),
        "reference": "https://github.com/advisories/GHSA-g93w-mfhg-p222",
        "exploited_in_wild": False,
    },

    # ════════════════ Vue.js ecosystem (v10.16, ověřeno přes web 2026-05) ════════════════
    {
        "library": "vue",
        "cve": "CVE-2024-6783",
        # vue-template-compiler (Vue 2) XSS přes prototype manipulation.
        # NENÍ ve Vue 3.
        "min_version": "2.0.0",
        "max_version": "3.0.0",
        "severity": "medium",
        "vector": "xss-template-compiler",
        "description": (
            "vue-template-compiler (Vue 2) XSS — manipulation of "
            "Object.prototype.staticClass/staticStyle via prototype chain "
            "allows arbitrary JS execution. Not present in Vue 3."
        ),
        "reference": "https://security.snyk.io/vuln/SNYK-JS-VUETEMPLATECOMPILER-7554675",
        "exploited_in_wild": False,
    },
]


# ── Semver parsing (shared logic with _dompurify_cve_feed) ───────────────────

def _parse_semver(ver: Optional[str]) -> Optional[Tuple[int, int, int, int]]:
    """Parse 'X.Y.Z' to a comparable tuple. Returns None if unparseable.

    Tolerant: '3.4' → (3,4,0,1), '3.4.1-beta' → (3,4,1,0).
    The 4th element encodes SemVer pre-release ordering: a pre-release sorts
    BEFORE its final release, so '3.4.0-beta' < '3.4.0'. Without this a
    pre-release of the FIXED (max_version) release parses equal to the fix and
    is wrongly treated as patched (false negative at the upper boundary).
    Build metadata ('+build') does NOT affect precedence (per SemVer).
    """
    if not ver:
        return None
    core = ver.split("+")[0].strip()          # drop build metadata (no precedence)
    is_prerelease = "-" in core               # e.g. 3.4.0-beta
    clean = core.split("-")[0].strip()
    parts = clean.split(".")
    try:
        nums = [int(p) for p in parts[:3]]
    except ValueError:
        return None
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2], 0 if is_prerelease else 1)


def _version_in_range(ver: str, min_ver: Optional[str],
                       max_ver: Optional[str]) -> bool:
    """Check if min_ver <= ver < max_ver.

    min_ver=None means "no lower bound" (any version up to max_ver).
    max_ver=None means "no upper bound" (any version from min_ver up).
    """
    v = _parse_semver(ver)
    if not v:
        return False
    if min_ver is not None:
        lo = _parse_semver(min_ver)
        if lo and v < lo:
            return False
    if max_ver is not None:
        hi = _parse_semver(max_ver)
        if hi and v >= hi:
            return False
    return True


# ── Library detection ─────────────────────────────────────────────────────────

def detect_library_from_filename(filename_or_url: str) -> Optional[Tuple[str, Optional[str]]]:
    """Identify library + version from a filename or URL.

    Returns (library_name, version) or None.
    version may be None if the filename matched but had no version
    (caller should then try detect_library_version_from_source).

    Examples:
      "jquery-1.11.3.min.js"          → ("jquery", "1.11.3")
      "/vendor/lodash.min.js"          → ("lodash", None)
      "https://x.com/js/bootstrap.js"  → ("bootstrap", None)
      "app.js"                         → None
    """
    if not filename_or_url:
        return None
    # Extract just the filename component if it's a URL/path
    fname = filename_or_url
    if "/" in fname:
        fname = fname.rsplit("/", 1)[-1]
    # Strip query string
    if "?" in fname:
        fname = fname.split("?")[0]

    # v10.16: zkoušej specifičtější názvy dřív (react-router před react,
    # angular-modern před angular) — jinak by 'react-router.js' chytlo
    # 'react'. Řadíme klíče podle délky názvu sestupně.
    for lib_name in sorted(_LIBRARY_FILENAME_PATTERNS.keys(),
                           key=len, reverse=True):
        patterns = _LIBRARY_FILENAME_PATTERNS[lib_name]
        for rx in patterns:
            m = rx.search(fname)
            if m:
                # First pattern with capture group has version
                version = m.group(1) if m.groups() else None
                return (lib_name, version)
    return None


def detect_library_version_from_source(library: str,
                                        source_code: str) -> Optional[str]:
    """Extract library version from inside its source code.

    Used when filename detection found the library but no version
    (e.g. "lodash.min.js" without version in the name).
    """
    if not library or not source_code:
        return None
    patterns = _LIBRARY_SOURCE_VERSION_PATTERNS.get(library, [])
    for rx in patterns:
        m = rx.search(source_code)
        if m:
            return m.group(1)
    return None


# ── CVE matching ──────────────────────────────────────────────────────────────

def match_cves_for_library(library: str,
                            version: Optional[str]) -> List[Dict]:
    """Return all CVE dicts affecting the given library + version.

    Empty list if library unknown, version None/unparseable, or version
    is in a safe (patched) range. Returns copies so caller can mutate.
    """
    if not library or not version:
        return []
    library = library.lower()
    matched: List[Dict] = []
    for entry in LIBRARY_CVE_FEED:
        if entry["library"] != library:
            continue
        if _version_in_range(version, entry.get("min_version"),
                              entry.get("max_version")):
            matched.append(dict(entry))
    return matched


def audit_library_file(filename_or_url: str,
                        source_code: Optional[str] = None) -> Optional[Dict]:
    """Full audit: detect library + version, match CVEs.

    Returns a dict:
      {
        "library": "jquery",
        "version": "1.11.3",
        "version_source": "filename" | "source" | "unknown",
        "matched_cves": [ {cve dict}, ... ],
        "cve_count": 5,
        "max_severity": "high",
        "exploited_in_wild": True,   # any matched CVE is in CISA KEV
      }
    or None if no library detected.
    """
    detection = detect_library_from_filename(filename_or_url)
    if not detection:
        return None
    library, version = detection
    version_source = "filename" if version else "unknown"

    # If filename had no version, try extracting from source
    if not version and source_code:
        version = detect_library_version_from_source(library, source_code)
        if version:
            version_source = "source"

    matched = match_cves_for_library(library, version) if version else []

    # Compute aggregate severity (highest wins)
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    max_sev = "info"
    max_rank = 0
    exploited = False
    for cve in matched:
        rank = severity_rank.get(cve.get("severity", "low"), 0)
        if rank > max_rank:
            max_rank = rank
            max_sev = cve.get("severity", "low")
        if cve.get("exploited_in_wild"):
            exploited = True

    return {
        "library": library,
        "version": version,
        "version_source": version_source,
        "matched_cves": matched,
        "cve_count": len(matched),
        "max_severity": max_sev if matched else "info",
        "exploited_in_wild": exploited,
    }


# v10.16: HTML-based framework detection. SPA frameworky (Angular 2+, Next.js)
# často nemají verzi v názvu JS bundlu (main.<hash>.js) — verze žije v HTML
# markeru. Tohle skenuje page HTML a vrací audity pro nalezené frameworky.
_HTML_FRAMEWORK_MARKERS = {
    "angular-modern": [
        re.compile(r'ng-version=["\'](\d+\.\d+\.\d+)["\']', re.IGNORECASE),
    ],
    "next": [
        re.compile(r'"next"\s*:\s*"(\d+\.\d+\.\d+)"', re.IGNORECASE),
    ],
}


def audit_html_for_frameworks(html: str) -> List[Dict]:
    """v10.16: Detekuje SPA frameworky z HTML markerů (ng-version, Next data)
    a vrátí audit dict pro každý s verzí. Komplementární k audit_library_file
    (ten řeší JS soubory podle názvu). Vrací jen frameworky s nalezenou verzí.
    """
    if not html:
        return []
    out: List[Dict] = []
    seen: set = set()
    for lib, patterns in _HTML_FRAMEWORK_MARKERS.items():
        for pat in patterns:
            m = pat.search(html)
            if not m:
                continue
            version = m.group(1)
            if (lib, version) in seen:
                continue
            seen.add((lib, version))
            matched = match_cves_for_library(lib, version)
            severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            max_sev, max_rank, exploited = "info", 0, False
            for cve in matched:
                rank = severity_rank.get(cve.get("severity", "low"), 0)
                if rank > max_rank:
                    max_rank, max_sev = rank, cve.get("severity", "low")
                if cve.get("exploited_in_wild"):
                    exploited = True
            out.append({
                "library": lib,
                "version": version,
                "version_source": "html-marker",
                "matched_cves": matched,
                "cve_count": len(matched),
                "max_severity": max_sev if matched else "info",
                "exploited_in_wild": exploited,
            })
            break
    return out


# ── Stats helpers (for engine logging / tests) ───────────────────────────────

def feed_size() -> int:
    """Number of CVE entries in feed."""
    return len(LIBRARY_CVE_FEED)


def tracked_libraries() -> List[str]:
    """List of library names with CVE coverage."""
    return sorted(set(e["library"] for e in LIBRARY_CVE_FEED))


def feed_cve_list() -> List[str]:
    """All unique CVE IDs in feed."""
    return sorted(set(e["cve"] for e in LIBRARY_CVE_FEED))


def cve_summary(library: str, version: Optional[str]) -> str:
    """Human-readable summary for a library+version.

    Returns e.g. "jquery 1.11.3: 5 CVEs (1 exploited in wild)" or
    "jquery 3.6.0: no known CVEs".
    """
    audit = audit_library_file(f"{library}-{version}.js") if version else None
    if not audit or not audit["matched_cves"]:
        return f"{library} {version or '?'}: no known CVEs"
    n = audit["cve_count"]
    exploited = sum(1 for c in audit["matched_cves"]
                     if c.get("exploited_in_wild"))
    exploited_note = (f" ({exploited} exploited in wild)"
                       if exploited else "")
    return f"{library} {version}: {n} CVE{'s' if n != 1 else ''}{exploited_note}"
