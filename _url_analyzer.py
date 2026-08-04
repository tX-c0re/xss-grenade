"""
_url_analyzer.py
================
Determines *where in a URL* the marker landed, so the tool can pick the
right bank of payloads (javascript: scheme vs. path-injection vs. query).

We don't need to parse the URL itself through urlparse if we know the
offset of the marker *within the attribute value* — we just walk the
string.

A URL attribute value looks like:

    <scheme>://<host>/<path>?<query>#<fragment>
    javascript:<code>
    data:<mime>,<payload>
    /relative/path
    ../relative
    mailto:user@host

We produce SubContext.URL_* hints.
"""

from __future__ import annotations

from context_engine import SubContext  # type: ignore[import-not-found]


_JS_SCHEME_PREFIX   = "javascript:"
_DATA_SCHEME_PREFIX = "data:"


def classify_url_subcontext(attr_value: str, local_offset: int) -> SubContext:
    """Given the raw attribute value and offset of marker inside it, return
    a URL sub-context."""
    if local_offset < 0 or local_offset > len(attr_value):
        return SubContext.URL_PATH

    low = attr_value.lower()

    # javascript: and data: schemes — if marker lands after the scheme prefix,
    # we're executing as JS (javascript:) or embedded document (data:)
    if low.startswith(_JS_SCHEME_PREFIX):
        if local_offset >= len(_JS_SCHEME_PREFIX):
            return SubContext.URL_JAVASCRIPT_SCHEME
        return SubContext.URL_SCHEME
    if low.startswith(_DATA_SCHEME_PREFIX):
        if local_offset >= len(_DATA_SCHEME_PREFIX):
            return SubContext.URL_DATA_SCHEME
        return SubContext.URL_SCHEME

    # Scheme section — up to the first ":"
    scheme_end = attr_value.find(":")
    if scheme_end != -1 and local_offset < scheme_end:
        return SubContext.URL_SCHEME

    # After scheme: find "//" → authority
    after_scheme_start = scheme_end + 1 if scheme_end != -1 else 0
    authority_markers = "//"
    authority_start = attr_value.find(authority_markers, after_scheme_start)
    host_start = -1
    host_end = -1
    if authority_start != -1 and authority_start == after_scheme_start:
        host_start = authority_start + 2
        # Host ends at first "/", "?", "#" or EOF
        for ch_idx, ch in enumerate(attr_value[host_start:], start=host_start):
            if ch in "/?#":
                host_end = ch_idx
                break
        else:
            host_end = len(attr_value)
        if host_start <= local_offset < host_end:
            return SubContext.URL_HOST

    # Fragment?
    frag = attr_value.find("#")
    if frag != -1 and local_offset >= frag:
        return SubContext.URL_FRAGMENT

    # Query?
    q = attr_value.find("?")
    if q != -1 and local_offset >= q:
        return SubContext.URL_QUERY

    return SubContext.URL_PATH
