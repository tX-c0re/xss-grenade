#!/usr/bin/env python3
"""
repro_level2.py — věrný mock Google XSS-game level 2 (stored XSS přes innerHTML).
Posty se doručují přes XHR /posts a renderují klientsky přes innerHTML (jako level 2).
Důkaz: HTTP-only verify mezi exec/ne-exec NEROZLIŠÍ; headless verify_url ANO.
"""
import json, threading, http.server, socketserver, urllib.parse
import requests, logging; logging.disable(logging.CRITICAL)

POSTS = []
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, body, ctype="text/html; charset=utf-8", code=200):
        b = body.encode(); self.send_response(code)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path.startswith("/posts"):
            return self._send(json.dumps(POSTS), "application/json")
        # věrné level-2: posty se NAČTOU přes XHR a renderují přes innerHTML
        self._send(
            "<!doctype html><html><body>"
            "<form method=POST action='/'><input name=msg><button>post</button></form>"
            "<div id=board></div>"
            "<script>"
            "fetch('/posts').then(function(r){return r.json();}).then(function(d){"
            "document.getElementById('board').innerHTML="
            "d.map(function(p){return '<div>'+p+'</div>';}).join('');});"
            "</script></body></html>")
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        POSTS.append(urllib.parse.parse_qs(self.rfile.read(n).decode()).get("msg", [""])[0])
        self.send_response(302); self.send_header("Location", "/"); self.end_headers()

srv = socketserver.TCPServer(("127.0.0.1", 0), H); srv.daemon_threads = True
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{srv.server_address[1]}/"
print(f"mock level2 (XHR/innerHTML) @ {base}")

img_m, scr_m = "XSGIMG777", "XSGSCR888"
requests.post(base, data={"msg": f'M"><img src=x onerror=alert("{img_m}")>'}, timeout=5)
requests.post(base, data={"msg": f'<script>alert("{scr_m}")</script>'}, timeout=5)

body = requests.get(base, timeout=5).text
posts = requests.get(base + "posts", timeout=5).text
print("\n[HTTP-only verify — co stored cesta dnes dělá]")
print(f"  img marker v /posts:    {img_m in posts}")
print(f"  script marker v /posts: {scr_m in posts}")
print("  → HTTP vidí oba, NEumí říct, který se SPUSTÍ (a /posts není ani hlavní page).")

from _headless_verifier import HeadlessVerifier
print("\n[Headless verify_url — navrhovaná oprava]")
with HeadlessVerifier(timeout_s=10.0, framework_wait_ms=1500, screenshot=False) as hv:
    vi = hv.verify_url(base, expect_canary=img_m, framework_wait=True)
    vs = hv.verify_url(base, expect_canary=scr_m, framework_wait=True)
    print(f"  <img onerror> → {vi.status.value:13} executed={vi.executed} method={vi.method!r}")
    print(f"  <script>      → {vs.status.value:13} executed={vs.executed} method={vs.method!r}")
print("\nZÁVĚR: headless rozliší proven TP (img) od ne-exec (script); HTTP ne.")
srv.shutdown()
