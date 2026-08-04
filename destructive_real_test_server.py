"""
Vulnerable server pro destructive E2E testy XSS Grenade.

Spustí HTTP server na 127.0.0.1:<port> s následujícími endpointy:

═══ Cache Poisoning (3 endpointy) ═══
  /cache/body         - X-Forwarded-Host reflektovaný v body + cache headers
  /cache/location     - X-Forwarded-Host reflektovaný v Location header
  /cache/cookie       - X-Forwarded-Host reflektovaný v Set-Cookie
  /cache/safe         - správně escaped, žádná reflection

═══ Host Header Reset (2 endpointy) ═══
  /forgot-password    - simuluje password reset s evil Host echo
  /password-reset     - alternativní path
  /safe-reset         - bezpečná verze (žádný Host echo)

═══ Stored XSS via headers (2 endpointy) ═══
  /track              - logger: ukládá Referer/User-Agent/X-Forwarded-For
  /admin/logs         - admin panel renderující logged hodnoty (XSS sink)
  /safe-track         - bezpečná verze (escapuje)

═══ Diagnostické endpointy ═══
  /                   - homepage
  /robots.txt         - pro warm-up sequence
  /favicon.ico        - pro warm-up sequence
  /reset-state        - vyčistí logged state (pro test izolaci)
  /state              - vrátí current state pro test verifikaci

Server zaznamenává všechny destructive akce do interního state, který
test runner kontroluje pro verifikaci, že payload byl skutečně uložen
(= reálný impact, ne jen reflection).
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote
import threading
import json
import html as html_module


# ═══════════════════════ STATE ═══════════════════════
# Vše thread-safe, sdílené napříč requesty.

_STATE_LOCK = threading.Lock()
_STATE = {
    # Cache poisoning — uložené poisoned values per endpoint
    "cache_body_value": None,
    "cache_location_value": None,
    "cache_cookie_value": None,

    # Host Header — kdy přišel POST + s jakým Host
    "reset_requests": [],

    # Stored XSS — všechny zalogované Referer/UA/XFF entries
    "tracked_headers": [],
}


def _get_state():
    with _STATE_LOCK:
        return dict(_STATE)


def _reset_state():
    with _STATE_LOCK:
        _STATE["cache_body_value"] = None
        _STATE["cache_location_value"] = None
        _STATE["cache_cookie_value"] = None
        _STATE["reset_requests"] = []
        _STATE["tracked_headers"] = []


# ═══════════════════════ HANDLER ═══════════════════════

class VulnHandler(BaseHTTPRequestHandler):

    def log_message(self, *args, **kwargs):
        # Tichý — testy nepotřebují HTTP access log
        pass

    def _send(self, status, body, content_type="text/html",
              extra_headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8", errors="replace")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_raw(self, raw_bytes):
        """Pošle raw bytes — pro testy které vyžadují nestandardní
        HTTP response (např. CRLF v Location header)."""
        try:
            self.wfile.write(raw_bytes)
        except Exception:
            pass

    # ═══════════ GET ═══════════
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        # Pro diagnostické endpointy
        if path == "/state":
            self._send(200, json.dumps(_get_state(), default=str),
                       content_type="application/json")
            return
        if path == "/reset-state":
            _reset_state()
            self._send(200, '{"ok":true}',
                       content_type="application/json")
            return

        # Warm-up endpointy
        if path == "/":
            body = (
                "<!doctype html><html><head><title>Vuln Lab</title>"
                "</head><body><h1>Destructive Test Lab</h1>"
                "<p>Local destructive test target.</p></body></html>"
            )
            self._send(200, body)
            return
        if path == "/robots.txt":
            self._send(200, "User-agent: *\nAllow: /\n",
                       content_type="text/plain")
            return
        if path == "/favicon.ico":
            # Minimal valid ICO
            self._send(200, b"\x00\x00\x01\x00",
                       content_type="image/x-icon")
            return

        # ═══ Cache poisoning endpointy ═══
        if path == "/cache/body":
            # VULNERABLE: X-Forwarded-Host se reflektuje v body BEZ escape
            # + cache headers (server "cachuje" payload pro všechny)
            xfh = self.headers.get("X-Forwarded-Host", "")
            # Uložit aktuální poison hodnotu — test runner si ověří
            # že server přijal a "cachoval" payload
            with _STATE_LOCK:
                if xfh and xfh != _STATE["cache_body_value"]:
                    _STATE["cache_body_value"] = xfh
            cached = _STATE["cache_body_value"] or "default-host"
            body = (
                f"<html><body>Welcome! Login at "
                f'<a href="https://{cached}/login">{cached}/login</a>'
                f"</body></html>"
            )
            self._send(200, body, extra_headers={
                "Age": "120",
                "X-Cache": "HIT",
                "CF-Cache-Status": "HIT",
                "Cache-Control": "public, max-age=3600",
            })
            return

        if path == "/cache/location":
            # VULNERABLE: X-Forwarded-Host se reflektuje v Location
            xfh = self.headers.get("X-Forwarded-Host", "")
            target = xfh or "localhost"
            with _STATE_LOCK:
                if xfh:
                    _STATE["cache_location_value"] = xfh
            self.send_response(302)
            self.send_header("Location", f"https://{target}/welcome")
            self.send_header("X-Cache", "HIT")
            self.send_header("Age", "60")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/cache/cookie":
            # VULNERABLE: X-Forwarded-Host se objeví v Set-Cookie domain
            xfh = self.headers.get("X-Forwarded-Host", "")
            with _STATE_LOCK:
                if xfh:
                    _STATE["cache_cookie_value"] = xfh
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            cookie_domain = xfh or "localhost"
            self.send_header(
                "Set-Cookie",
                f"session=abc; Domain={cookie_domain}; Path=/",
            )
            self.send_header("X-Cache", "MISS")
            body = b"<html><body>session set</body></html>"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/cache/safe":
            # SAFE: NEEXISTUJÍCÍ reflection, žádné cache headers
            body = "<html><body>safe page</body></html>"
            self._send(200, body)
            return

        # ═══ Host Header reset endpointy (GET — probe) ═══
        if path in ("/forgot-password", "/password-reset",
                    "/safe-reset", "/forgot"):
            # GET probe — endpoint existuje
            body = (
                "<html><body><form method='post'>"
                "<input name='email' placeholder='your email'>"
                "<button>Reset Password</button>"
                "</form></body></html>"
            )
            self._send(200, body)
            return

        # ═══ Stored XSS via headers endpointy ═══
        if path == "/track":
            # VULNERABLE: zaznamenává Referer/User-Agent/X-Forwarded-For
            # bez sanitize. Tyto hodnoty pak admin panel renderuje.
            entry = {
                "referer": self.headers.get("Referer", ""),
                "user_agent": self.headers.get("User-Agent", ""),
                "x_forwarded_for": self.headers.get(
                    "X-Forwarded-For", ""),
                "via": self.headers.get("Via", ""),
                "from": self.headers.get("From", ""),
                "client_ip": self.headers.get("Client-IP", ""),
                "true_client_ip": self.headers.get(
                    "True-Client-IP", ""),
            }
            with _STATE_LOCK:
                _STATE["tracked_headers"].append(entry)
            self._send(200, b"tracked",
                       content_type="text/plain")
            return

        if path == "/safe-track":
            # SAFE varianta — necachuje user input do logu
            self._send(200, b"tracked", content_type="text/plain")
            return

        if path == "/admin/logs":
            # SINK: renderuje logged hodnoty BEZ escape.
            # Pokud stored XSS vektor uspěl, admin tady uvidí payload
            # spustit v jeho browseru.
            with _STATE_LOCK:
                logs = list(_STATE["tracked_headers"])
            parts = ["<html><body><h1>Admin Logs</h1><table>"]
            parts.append(
                "<tr><th>Referer</th><th>User-Agent</th>"
                "<th>X-Forwarded-For</th><th>Via</th></tr>"
            )
            for e in logs:
                # ZRANITELNÉ: payload se renderuje bez escape
                parts.append(
                    f"<tr><td>{e['referer']}</td>"
                    f"<td>{e['user_agent']}</td>"
                    f"<td>{e['x_forwarded_for']}</td>"
                    f"<td>{e['via']}</td></tr>"
                )
            parts.append("</table></body></html>")
            self._send(200, "".join(parts))
            return

        if path == "/admin/logs-safe":
            # SAFE varianta — html.escape všech hodnot
            with _STATE_LOCK:
                logs = list(_STATE["tracked_headers"])
            parts = ["<html><body><h1>Admin Logs (safe)</h1><table>"]
            for e in logs:
                parts.append(
                    f"<tr><td>{html_module.escape(e['referer'])}</td>"
                    f"<td>{html_module.escape(e['user_agent'])}</td>"
                    f"</tr>"
                )
            parts.append("</table></body></html>")
            self._send(200, "".join(parts))
            return

        # Fallback
        self._send(404, b"not found", content_type="text/plain")

    # ═══════════ POST ═══════════
    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Body parse
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw_body = self.rfile.read(length) if length else b""
        try:
            form_data = parse_qs(raw_body.decode("utf-8",
                                                  errors="replace"))
        except Exception:
            form_data = {}

        # ═══ Host Header reset endpointy ═══
        if path in ("/forgot-password", "/password-reset", "/forgot"):
            # VULNERABLE: vrací Host header v body + simuluje email send
            host = self.headers.get("Host", "localhost")
            email = form_data.get("email", [""])[0]
            xfh = self.headers.get("X-Forwarded-Host", "")

            # Effective host pro reset link — vulnerable!
            # Server preferuje X-Forwarded-Host pokud je nastaven
            effective_host = xfh if xfh else host

            with _STATE_LOCK:
                _STATE["reset_requests"].append({
                    "endpoint": path,
                    "email": email,
                    "host_header": host,
                    "x_forwarded_host": xfh,
                    "effective_host_used_for_link": effective_host,
                })

            # Response echoes the effective host (= attacker-controlled)
            body = (
                f"<html><body><h2>Email Sent!</h2>"
                f"<p>Check your inbox. Reset link uses host: "
                f"{effective_host}</p>"
                f"<p>Sample reset URL (would be sent via email): "
                f"https://{effective_host}/reset?token=abc123&"
                f"email={email}</p>"
                f"</body></html>"
            )
            self._send(200, body)
            return

        if path == "/safe-reset":
            # SAFE: ignoruje X-Forwarded-Host, používá hard-coded host
            email = form_data.get("email", [""])[0]
            with _STATE_LOCK:
                _STATE["reset_requests"].append({
                    "endpoint": path,
                    "email": email,
                    "host_header": self.headers.get("Host", ""),
                    "x_forwarded_host": self.headers.get(
                        "X-Forwarded-Host", ""),
                    "effective_host_used_for_link": "vuln-lab.local",
                })
            body = (
                "<html><body><h2>Email Sent (safe).</h2>"
                "<p>Reset link uses hard-coded host vuln-lab.local.</p>"
                "</body></html>"
            )
            self._send(200, body)
            return

        self._send(404, b"not found", content_type="text/plain")


# ═══════════════════════ RUNNER ═══════════════════════

def run(port=8850, host="127.0.0.1"):
    """Spustí server na background threadu. Vrací HTTPServer instance,
    server.shutdown() pro graceful stop."""
    srv = HTTPServer((host, port), VulnHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def get_state():
    return _get_state()


def reset_state():
    _reset_state()


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8850
    srv = run(port=port)
    print(f"Vulnerable server running on http://127.0.0.1:{port}/")
    print("Endpoints:")
    print("  Cache:  /cache/body /cache/location /cache/cookie "
          "/cache/safe")
    print("  Reset:  /forgot-password /password-reset /safe-reset "
          "(POST)")
    print("  XSS:    /track (any GET) /admin/logs /admin/logs-safe")
    print("  Util:   /state /reset-state")
    print()
    print("Ctrl-C to stop.")
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.shutdown()
        print("Stopped.")
