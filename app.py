import json
import os
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TARGET_HOST = os.environ.get("TARGET_HOST", "").strip()
TARGET_PORT = int(os.environ.get("TARGET_PORT", "22"))
PROBE_TOKEN = os.environ.get("PROBE_TOKEN", "").strip()
PORT = int(os.environ.get("PORT", "8080"))


def probe():
    if not TARGET_HOST:
        return {"ok": False, "error": "TARGET_HOST is not configured"}
    try:
        with socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=8):
            return {"ok": True, "port": TARGET_PORT}
    except Exception as exc:
        return {"ok": False, "port": TARGET_PORT, "error": type(exc).__name__ + ": " + str(exc)}


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self._json(200, {"ok": True})
        if self.path == "/probe":
            if not PROBE_TOKEN:
                return self._json(503, {"ok": False, "error": "PROBE_TOKEN is not configured"})
            if self.headers.get("Authorization", "") != f"Bearer {PROBE_TOKEN}":
                return self._json(401, {"ok": False, "error": "unauthorized"})
            result = probe()
            return self._json(200 if result["ok"] else 502, result)
        return self._json(404, {"ok": False, "error": "not found"})

    def log_message(self, fmt, *args):
        print("http", self.address_string(), fmt % args, flush=True)


if __name__ == "__main__":
    print("startup_probe", json.dumps(probe(), ensure_ascii=False), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
