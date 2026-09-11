from __future__ import annotations

import json
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

from sentinel_dns.state import AppState

STATIC = Path(__file__).resolve().parent / "web" / "static"
MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json",
}


class Handler(BaseHTTPRequestHandler):
    state: AppState

    def log_message(self, fmt: str, *args) -> None:
        return

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in {"/", "/index.html"}:
            self._file(STATIC / "index.html")
            return
        if path.startswith("/static/"):
            rel = path[len("/static/") :]
            target = (STATIC / rel).resolve()
            if STATIC not in target.parents and target != STATIC:
                self._send(403, b"forbidden", "text/plain")
                return
            self._file(target)
            return
        if path == "/api/state":
            snap = self.state.snapshot()
            with self.state.lock:
                snap["alerts"] = self.state.alerts[:12]
            body = json.dumps(snap, ensure_ascii=False, default=str).encode("utf-8")
            self._send(200, body, "application/json; charset=utf-8")
            return
        if path == "/health":
            self._send(200, b'{"ok":true}', "application/json")
            return
        self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        if path in {"/ingest/wazuh", "/api/wazuh"}:
            try:
                payload = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                self._send(400, b'{"error":"invalid json"}', "application/json")
                return
            with self.state.lock:
                self.state.alerts.insert(0, payload)
                del self.state.alerts[80:]
            self._send(200, b'{"accepted":true}', "application/json")
            return
        self._send(404, b"not found", "text/plain")

    def _file(self, path: Path) -> None:
        if not path.is_file():
            self._send(404, b"not found", "text/plain")
            return
        data = path.read_bytes()
        self._send(200, data, MIME.get(path.suffix, "application/octet-stream"))


def serve(state: AppState, host: str, port: int) -> ThreadingHTTPServer:
    handler = type("H", (Handler,), {"state": state})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    return httpd
