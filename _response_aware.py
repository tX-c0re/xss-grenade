"""
_response_aware.py
==================
Content-Type aware classification adjustments.

Background
----------
The example.com report contains 12 hits on `/api/contact/<lang>` POST
endpoints, all returning a JSON response, where the payload was
reflected as a string FIELD inside JSON. This is NOT a browser-renderable
context — the response is `application/json`, which the browser will
NOT parse as HTML.

The only way such a reflection becomes XSS is if a JS client takes
the JSON field and assigns it to `innerHTML` somewhere. That requires
DOM analysis, not response-only analysis.

What this module does
---------------------
1. Inspect Content-Type header
2. If non-HTML (json/xml/plain text/binary), automatically DOWNGRADE
   the severity to "informational" unless the caller has positive
   evidence of a DOM sink consuming the field.
3. Add explicit reasoning to the finding so reports show WHY it's
   downgraded.

Public API
----------

    classify_response_renderability(content_type, body)
        → RenderabilityVerdict

    apply_downgrade(rich_context, verdict, exploit_verdict)
        → adjusted (severity, klass, notes)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


class Renderability(str, Enum):
    HTML_RENDERED       = "html_rendered"        # browser parses as HTML
    JSON_API            = "json_api"             # application/json, NOT rendered
    XML_API             = "xml_api"              # application/xml
    PLAIN_TEXT          = "plain_text"           # text/plain
    BINARY              = "binary"               # octet-stream, image, etc.
    JAVASCRIPT_RESPONSE = "javascript_response"  # text/javascript — special: still
                                                  #   could exec if loaded as <script src=…>
    UNKNOWN             = "unknown"


@dataclass
class RenderabilityVerdict:
    renderability: Renderability
    content_type:  str
    notes:         List[str] = field(default_factory=list)

    @property
    def is_browser_rendered_html(self) -> bool:
        return self.renderability == Renderability.HTML_RENDERED


# ══════════════════════════════════════════════════════════════════════════════
# CONTENT-TYPE ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def classify_response_renderability(content_type: Optional[str],
                                     body: str = "") -> RenderabilityVerdict:
    """
    Determine if a response body will be HTML-rendered by a browser
    based on its Content-Type header.

    HTML is rendered ONLY if Content-Type is one of:
        text/html
        application/xhtml+xml
        application/xml + body looks like XHTML

    Anything else: NOT rendered as HTML.
    """
    ct = (content_type or "").lower().split(";", 1)[0].strip()

    if ct in ("text/html", "application/xhtml+xml"):
        return RenderabilityVerdict(
            renderability=Renderability.HTML_RENDERED,
            content_type=ct,
        )

    if ct in ("application/json", "application/ld+json", "application/manifest+json",
              "application/problem+json", "text/json"):
        return RenderabilityVerdict(
            renderability=Renderability.JSON_API,
            content_type=ct,
            notes=["browser_does_not_render_json_as_html",
                   "exploitable_only_if_dom_sink_uses_innerHTML_with_field"],
        )

    if ct in ("application/xml", "text/xml", "application/rss+xml",
              "application/atom+xml"):
        # XML can be HTML-ish if it's actually XHTML and browser navigates
        # directly to it. Most XML APIs do not render markup.
        return RenderabilityVerdict(
            renderability=Renderability.XML_API,
            content_type=ct,
            notes=["xml_response_not_rendered_as_html_by_default"],
        )

    if ct in ("text/javascript", "application/javascript",
              "application/x-javascript"):
        return RenderabilityVerdict(
            renderability=Renderability.JAVASCRIPT_RESPONSE,
            content_type=ct,
            notes=["js_response_executable_only_if_loaded_as_script_tag",
                   "JSONP_endpoints_exploitable_via_callback_param"],
        )

    if ct.startswith("text/plain"):
        return RenderabilityVerdict(
            renderability=Renderability.PLAIN_TEXT,
            content_type=ct,
            notes=["plain_text_not_rendered_as_html"],
        )

    if (ct.startswith(("image/", "audio/", "video/", "font/"))
            or ct in ("application/octet-stream", "application/pdf",
                       "application/zip")):
        return RenderabilityVerdict(
            renderability=Renderability.BINARY,
            content_type=ct,
            notes=["binary_response_no_html_parsing"],
        )

    # Unknown / missing Content-Type
    if not ct:
        # Check body shape — does it start with "<"? Then probably HTML.
        bstart = body.lstrip()[:128].lower() if body else ""
        if bstart.startswith(("<!doctype", "<html", "<?xml", "<")):
            return RenderabilityVerdict(
                renderability=Renderability.HTML_RENDERED,
                content_type="(missing)",
                notes=["content_type_missing_but_body_looks_like_html"],
            )
        if bstart.startswith(("{", "[")):
            return RenderabilityVerdict(
                renderability=Renderability.JSON_API,
                content_type="(missing)",
                notes=["content_type_missing_but_body_looks_like_json"],
            )

    return RenderabilityVerdict(
        renderability=Renderability.UNKNOWN,
        content_type=ct or "(missing)",
        notes=["content_type_unrecognized"],
    )


# ══════════════════════════════════════════════════════════════════════════════
# JSON FIELD REFLECTION CHECK
# ══════════════════════════════════════════════════════════════════════════════

def is_payload_just_json_string_field(body: str, payload: str) -> bool:
    """
    For a JSON response, check if the payload appears ONLY as a value of
    a JSON string field (like `{"name": "<payload>"}`). If yes, it's
    properly JSON-encoded and even if served with wrong Content-Type,
    a typical JS client would not render it as HTML.

    Returns True only if the JSON parses AND the payload is found inside
    a string value (not as a key, not in raw markup).
    """
    if not body or not payload:
        return False
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return False

    def walk(node) -> bool:
        if isinstance(node, str):
            return payload in node
        if isinstance(node, dict):
            return any(walk(v) for v in node.values())
        if isinstance(node, list):
            return any(walk(item) for item in node)
        return False

    return walk(data)


# ══════════════════════════════════════════════════════════════════════════════
# DOWNGRADE LOGIC
# ══════════════════════════════════════════════════════════════════════════════

# Severity ordering for downgrade
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3,
                   "informational": -1}


def apply_downgrade(severity: str,
                     renderability: RenderabilityVerdict) -> Tuple[str, List[str]]:
    """
    Adjust severity based on response renderability.

    Returns (new_severity, notes_added).

    Rules:
        HTML_RENDERED        → no change
        JSON_API             → cap at "low" (informational only)
        XML_API              → cap at "medium"
        JAVASCRIPT_RESPONSE  → keep severity (could be JSONP exploit)
        PLAIN_TEXT           → cap at "low"
        BINARY               → cap at "informational"
        UNKNOWN              → no change but add note
    """
    notes: List[str] = []
    new_sev = severity

    rb = renderability.renderability

    if rb == Renderability.HTML_RENDERED:
        return severity, []

    if rb == Renderability.JSON_API:
        if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK["low"]:
            new_sev = "low"
            notes.append(f"downgraded_from_{severity}_due_to_JSON_response")
        notes.append("verify_via_DOM_analysis_if_field_consumed_by_innerHTML")
        return new_sev, notes

    if rb == Renderability.XML_API:
        if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK["medium"]:
            new_sev = "medium"
            notes.append(f"downgraded_from_{severity}_due_to_XML_response")
        return new_sev, notes

    if rb == Renderability.PLAIN_TEXT:
        if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK["low"]:
            new_sev = "low"
            notes.append(f"downgraded_from_{severity}_due_to_plain_text_response")
        return new_sev, notes

    if rb == Renderability.BINARY:
        new_sev = "informational"
        notes.append(f"downgraded_from_{severity}_due_to_binary_response")
        return new_sev, notes

    if rb == Renderability.JAVASCRIPT_RESPONSE:
        notes.append("response_is_javascript_check_for_JSONP_exploit")
        return severity, notes

    notes.append(f"unknown_renderability_for_{renderability.content_type}")
    return severity, notes
