#!/usr/bin/env python3
"""
fr_server.py — a faithful Python port of the subset of Google's Firing Range
(https://github.com/google/firing-range) that is relevant to an XSS scanner.

WHY THIS EXISTS
---------------
The in-repo `benchmark_scoreboard.py` corpus was authored by this project, so a
perfect score on it proves only self-consistency. Firing Range is an
INDEPENDENT, purpose-built XSS-scanner benchmark written by Google's security
team. Its page templates are used here VERBATIM (see templates/, Apache-2.0,
LICENSE.firing-range) — nothing about the corpus was authored or tuned by us.

Firing Range itself is a Java/AppEngine app and cannot run in this environment
(no JVM), so the handful of servlets that generate the XSS corpus are ported
here 1:1. The port is deliberately mechanical:

  reflected.Parameter          -> /reflected/parameter/<template>?q=
  reflected.EscapedParameter   -> /reflected/escapedparameter/<template>/<escaper>?q=
  address.Address              -> /address/<source>/<sink>

Semantics preserved from the original Java:
  * Templates.getTemplate() takes the FIRST path component as the template name;
    EscapedParameter takes the SECOND as the escaper (Escaper.EscapeMode).
  * Responses.sendXssed() serves EVERY page as `text/html; charset=utf-8`
    with `X-XSS-Protection: 0` and no-store caching — including json.tmpl.
  * Escaper.EscapeMode escapes exactly the characters Google's Escaper.java does
    (a set of deliberately PARTIAL escapers — that is the point of the corpus).

Ground truth is NOT hardcoded here. It is measured empirically by fr_oracle.py,
which drives a real Chromium against every endpoint with a fixed battery of
public XSS payloads. See that file.
"""
import http.server
import os
import socketserver
import threading
import urllib.parse
from urllib.parse import urlparse, parse_qs

_HERE = os.path.dirname(os.path.abspath(__file__))
_TPL = os.path.join(_HERE, "templates")

PAYLOAD_PLACEHOLDER = "%%PAYLOAD%%"
ECHOED_PARAM = "q"  # reflected.Parameter.ECHOED_PARAM


# ── Escaper.java, ported verbatim ────────────────────────────────────────────
def _esc_double_quotes(s):
    """Escaper.escapesDoubleQuotes"""
    return s.replace('"', "&quot;")


def _esc_single_quotes(s):
    """Escaper.escapesSingleQuotes"""
    return s.replace("'", "&#39;")


def _esc_greater_than(s):
    """Escaper.escapesGreatherThan — 'simply prevent closing the tag'"""
    return s.replace(">", "&gt;")


def _esc_html(s):
    """Escaper.escapeHtml — NOTE the original's ordering (& is escaped AFTER
    the quote replacements, so &#39;/&quot; introduced above get double-escaped;
    reproduced exactly)."""
    return (s.replace("'", "&#39;")
             .replace('"', "&quot;")
             .replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;"))


ESCAPERS = {
    "DOUBLE_QUOTED_ATTRIBUTE": _esc_double_quotes,
    "SINGLE_QUOTED_ATTRIBUTE": _esc_single_quotes,
    "UNQUOTED_ATTRIBUTE": _esc_greater_than,
    "HTML": _esc_html,
}


# ── template loading ─────────────────────────────────────────────────────────
def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _load_dir(sub):
    out = {}
    d = os.path.join(_TPL, sub)
    if not os.path.isdir(d):
        return out
    for fn in os.listdir(d):
        if fn.endswith(".tmpl"):
            out[fn[:-5]] = _read(os.path.join(d, fn))
    return out


REFLECTED = _load_dir("reflected")
ADDR_SOURCES = _load_dir("address/sources")
ADDR_SINKS = _load_dir("address/sinks")
ADDR_BASE = _read(os.path.join(_TPL, "address", "address.tmpl"))


def replace_payload(template, payload):
    """Templates.replacePayload"""
    return template.replace(PAYLOAD_PLACEHOLDER, payload)


def render_address(source, sink):
    """Address.generateTemplate"""
    return replace_payload(ADDR_BASE, ADDR_SOURCES[source] + "\n" + ADDR_SINKS[sink])


# ── the full endpoint inventory (used by the oracle and the scorer) ──────────
def endpoints():
    """Every corpus endpoint as (kind, path, inject) where `inject` says how a
    payload reaches the page: 'query:q' | 'fragment' | 'path'."""
    eps = []
    for t in sorted(REFLECTED):
        eps.append(("reflected", f"/reflected/parameter/{t}", "query:q"))
    for t in sorted(REFLECTED):
        for e in sorted(ESCAPERS):
            eps.append(("escaped", f"/reflected/escapedparameter/{t}/{e}", "query:q"))
    for s in sorted(ADDR_SOURCES):
        for k in sorted(ADDR_SINKS):
            eps.append(("address", f"/address/{s}/{k}", "url"))
    return eps


def _links_for(eps):
    out = []
    for _kind, path, inject in eps:
        href = path + ("?q=test" if inject == "query:q" else "")
        out.append(f'<li><a href="{href}">{path}</a></li>')
    return "".join(out)


def _home():
    """Link every endpoint so a crawler can discover the corpus."""
    return ("<html><head><title>Firing Range (port)</title></head><body>"
            "<h1>Firing Range — XSS corpus (Google, ported)</h1><ul>"
            + _links_for(endpoints()) + "</ul></body></html>")


def batches(size, only=None):
    """Split the corpus into chunks of `size` endpoints.

    The engine caps some page-level phases (e.g. MAX_DOM_V6_PAGES = 25), so a
    single crawl over all 311 endpoints leaves most of them without DOM
    analysis — which measures the cap, not the detector. Scanning batch index
    pages keeps every phase's page budget non-binding.
    """
    eps = [e for e in endpoints() if not only or e[0] in only]
    return [eps[i:i + size] for i in range(0, len(eps), size)]


def _batch_page(idx, size, only=None):
    bs = batches(size, only)
    if idx < 0 or idx >= len(bs):
        return None
    return ("<html><head><title>corpus batch %d</title></head><body><ul>%s</ul>"
            "</body></html>" % (idx, _links_for(bs[idx])))


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # Responses.sendXssed
    def _xssed(self, body, ctype="text/html; charset=utf-8", status=200):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("X-XSS-Protection", "0")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, msg, status=400):
        body = _esc_html(msg).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        self._dispatch(parse_qs(raw))

    def do_GET(self):
        self._dispatch(None)

    def _dispatch(self, post_params):
        u = urlparse(self.path)
        parts = [p for p in u.path.split("/") if p]
        q = parse_qs(u.query)
        if post_params:
            for k, v in post_params.items():
                q.setdefault(k, v)
        echoed = (q.get(ECHOED_PARAM) or [""])[0]

        if not parts or parts[0] in ("index.html",):
            return self._xssed(_home())

        # /batch/<size>/<index> — an index page listing only that slice of the
        # corpus, so per-phase page caps do not bind (see batches()).
        if parts[0] == "batch" and len(parts) >= 3:
            try:
                size, idx = int(parts[1]), int(parts[2])
            except ValueError:
                return self._error("bad batch spec", 400)
            only = set(parts[3].split(",")) if len(parts) >= 4 else None
            page = _batch_page(idx, size, only)
            if page is None:
                return self._error("batch out of range", 404)
            return self._xssed(page)

        # /reflected/parameter/<template>
        if len(parts) >= 3 and parts[0] == "reflected" and parts[1] == "parameter":
            tpl = REFLECTED.get(parts[2])
            if tpl is None:
                return self._error("Cannot find template", 404)
            return self._xssed(replace_payload(tpl, echoed))

        # /reflected/escapedparameter/<template>/<escaper>
        if len(parts) >= 4 and parts[0] == "reflected" and parts[1] == "escapedparameter":
            tpl = REFLECTED.get(parts[2])
            esc = ESCAPERS.get(parts[3])
            if tpl is None or esc is None:
                return self._error("Cannot find template/escaper", 404)
            return self._xssed(replace_payload(tpl, esc(echoed)))

        # /address/<source>/<sink>
        if len(parts) >= 3 and parts[0] == "address":
            if parts[1] not in ADDR_SOURCES or parts[2] not in ADDR_SINKS:
                return self._error("Malformed URL", 400)
            return self._xssed(render_address(parts[1], parts[2]))

        return self._xssed("<html><body>ok</body></html>", status=404)


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start(port=0):
    """Start the corpus server on `port` (0 = ephemeral). Returns (base_url, srv)."""
    srv = _Server(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}/", srv


if __name__ == "__main__":
    import sys
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 8781
    url, _srv = start(p)
    eps = endpoints()
    print(f"Firing Range (port) on {url}")
    print(f"  reflected : {sum(1 for e in eps if e[0] == 'reflected')}")
    print(f"  escaped   : {sum(1 for e in eps if e[0] == 'escaped')}")
    print(f"  address   : {sum(1 for e in eps if e[0] == 'address')}")
    print(f"  TOTAL     : {len(eps)}")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
