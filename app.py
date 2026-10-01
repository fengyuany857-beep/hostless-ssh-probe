from __future__ import annotations

import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from vcw_runner import Config, PolicyError, RPC_VERSION, RunnerService

CFG = Config.from_env()
SERVICE = RunnerService(CFG)
INFLIGHT = threading.BoundedSemaphore(CFG.max_inflight)


def audit(event: str, **data):
    print(json.dumps({"event": event, "ts": time.time(), **data}, ensure_ascii=False, separators=(",", ":"), sort_keys=True), flush=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "vcw-remote-runner/1"

    def _json(self, code: int, payload: dict, headers: dict[str, str] | None = None):
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        return hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {CFG.runner_token}")

    def do_GET(self):
        if self.path == "/health":
            return self._json(200, {"ok": True, "service": "vcw-remote-runner", "rpc_version": RPC_VERSION})
        if not self._authorized():
            return self._json(401, {"ok": False, "error": "unauthorized"})
        if self.path in {"/probe", "/v1/info"}:
            try:
                probe = SERVICE.backend.probe()
                if self.path == "/probe":
                    return self._json(200, probe)
                return self._json(200, {"ok": True, "rpc_version": RPC_VERSION, "server_id": CFG.server_id, "connection_generation": SERVICE.backend.generation, "backend": probe, "idempotency_ledger": {"backend": SERVICE.ledger.backend, "durable": SERVICE.ledger.durable}, "tools": sorted(CFG.allowed_tools)})
            except Exception as exc:
                return self._json(503, {"ok": False, "error": type(exc).__name__, "message": str(exc)})
        return self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        if self.path != "/v1/rpc":
            return self._json(404, {"ok": False, "error": "not found"})
        if not self._authorized():
            return self._json(401, {"ok": False, "error": "unauthorized"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._json(400, {"ok": False, "error": "invalid content length"})
        if length <= 0 or length > CFG.max_file_bytes + 1024 * 1024:
            return self._json(413, {"ok": False, "error": "request body too large"})
        try:
            body = json.loads(self.rfile.read(length))
        except Exception:
            return self._json(400, {"ok": False, "error": "invalid json"})
        if not isinstance(body, dict):
            return self._json(400, {"ok": False, "error": "RPC body must be an object"})

        if not INFLIGHT.acquire(blocking=False):
            rid = body.get("request_id", "")
            payload = {"rpc_version": RPC_VERSION, "request_id": rid, "server_id": CFG.server_id, "connection_generation": SERVICE.backend.generation, "status": "RATE_LIMITED", "result": None, "error": {"code": "RUNNER_INFLIGHT_LIMIT", "message": "runner concurrency cap reached"}}
            audit("rpc.rate_limited", request_id=rid, method=body.get("method"), reason="RUNNER_INFLIGHT_LIMIT")
            return self._json(429, payload, {"Retry-After": "1"})

        rid = body.get("request_id", "")
        method = body.get("method")
        started = time.time()
        try:
            response = SERVICE.dispatch(body)
            audit("rpc.completed", request_id=rid, method=method, status=response.get("status"), duration_ms=int((time.time() - started) * 1000), connection_generation=response.get("connection_generation"))
            return self._json(200, response)
        except PolicyError as exc:
            audit("rpc.denied", request_id=rid, method=method, reason=str(exc))
            return self._json(400, {"ok": False, "status": "DENIED", "error": {"code": "POLICY_DENIED", "message": str(exc)}})
        except Exception as exc:
            audit("rpc.failed", request_id=rid, method=method, error=type(exc).__name__)
            return self._json(500, {"ok": False, "status": "FAILED", "error": {"code": type(exc).__name__, "message": str(exc)}})
        finally:
            INFLIGHT.release()

    def log_message(self, fmt, *args):
        audit("http.access", client=self.client_address[0], message=fmt % args)


if __name__ == "__main__":
    audit("runner.start", server_id=CFG.server_id, port=CFG.port)
    ThreadingHTTPServer(("0.0.0.0", CFG.port), Handler).serve_forever()
