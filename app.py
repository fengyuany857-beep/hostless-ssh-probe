from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from vcw_runner import Config, PolicyError, RPC_VERSION, RunnerService

CFG = Config.from_env()
SERVICE = RunnerService(CFG)
INFLIGHT = threading.BoundedSemaphore(CFG.max_inflight)
REQUEST_BODY_LIMIT = ((CFG.max_file_bytes + 2) // 3) * 4 + 1024 * 1024
AUDIT_ID = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")


def safe_audit_id(value):
    return value if isinstance(value, str) and AUDIT_ID.fullmatch(value) else None


def safe_audit_method(value):
    return value if isinstance(value, str) and value in CFG.allowed_tools else None


def runtime_build_fingerprint() -> str:
    digest = hashlib.sha256()
    base = Path(__file__).resolve().parent
    for name in ("app.py", "vcw_runner.py", "channel_exec.py", "requirements.txt"):
        path = base / name
        data = path.read_bytes()
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(data)).encode("ascii"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


BUILD_FINGERPRINT = runtime_build_fingerprint()
BUILD_REVISION = os.environ.get("VCW_RUNNER_BUILD_REVISION", "").strip() or None


def reject_nonstandard_json_constant(value: str):
    raise ValueError(f"non-standard JSON constant is not allowed: {value}")


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
                return self._json(200, {"ok": True, "rpc_version": RPC_VERSION, "server_id": CFG.server_id, "connection_generation": SERVICE.backend.generation, "backend": probe, "idempotency_ledger": {"backend": SERVICE.ledger.backend, "durable": SERVICE.ledger.durable}, "build": {"fingerprint_sha256": BUILD_FINGERPRINT, "revision": BUILD_REVISION}, "tools": sorted(CFG.allowed_tools)})
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
        if length <= 0 or length > REQUEST_BODY_LIMIT:
            return self._json(413, {"ok": False, "error": "request body too large"})
        try:
            body = json.loads(self.rfile.read(length), parse_constant=reject_nonstandard_json_constant)
        except Exception:
            return self._json(400, {"ok": False, "error": "invalid json"})
        if not isinstance(body, dict):
            return self._json(400, {"ok": False, "error": "RPC body must be an object"})

        if not INFLIGHT.acquire(blocking=False):
            rid = safe_audit_id(body.get("request_id")) or ""
            method = safe_audit_method(body.get("method"))
            payload = {"rpc_version": RPC_VERSION, "request_id": rid, "server_id": CFG.server_id, "connection_generation": SERVICE.backend.generation, "status": "RATE_LIMITED", "result": None, "error": {"code": "RUNNER_INFLIGHT_LIMIT", "message": "runner concurrency cap reached"}}
            audit("rpc.rate_limited", request_id=rid or None, method=method, status="RATE_LIMITED", connection_generation=SERVICE.backend.generation)
            return self._json(429, payload, {"Retry-After": "1"})

        rid = safe_audit_id(body.get("request_id"))
        method = safe_audit_method(body.get("method"))
        started = time.time()
        try:
            response = SERVICE.dispatch(body)
            audit(
                "rpc.completed",
                request_id=rid,
                session_id=safe_audit_id(response.get("session_id")),
                method=method,
                status=response.get("status"),
                duration_ms=int((time.time() - started) * 1000),
                connection_generation=response.get("connection_generation"),
            )
            return self._json(200, response)
        except PolicyError as exc:
            audit("rpc.denied", request_id=rid, session_id=safe_audit_id(body.get("session_id")), method=method, status="DENIED", connection_generation=SERVICE.backend.generation)
            payload = {
                "rpc_version": RPC_VERSION,
                "request_id": rid or "",
                "server_id": CFG.server_id,
                "connection_generation": SERVICE.backend.generation,
                "status": "DENIED",
                "result": None,
                "error": {"code": "POLICY_DENIED", "message": str(exc)},
            }
            session_id = safe_audit_id(body.get("session_id"))
            if session_id is not None:
                payload["session_id"] = session_id
            return self._json(400, payload)
        except Exception as exc:
            audit("rpc.failed", request_id=rid, session_id=safe_audit_id(body.get("session_id")), method=method, status="FAILED", error=type(exc).__name__, connection_generation=SERVICE.backend.generation)
            payload = {
                "rpc_version": RPC_VERSION,
                "request_id": rid or "",
                "server_id": CFG.server_id,
                "connection_generation": SERVICE.backend.generation,
                "status": "FAILED",
                "result": None,
                "error": {"code": type(exc).__name__, "message": str(exc)},
            }
            session_id = safe_audit_id(body.get("session_id"))
            if session_id is not None:
                payload["session_id"] = session_id
            return self._json(500, payload)
        finally:
            INFLIGHT.release()

    def log_message(self, fmt, *args):
        audit("http.access", client=self.client_address[0], message=fmt % args)


if __name__ == "__main__":
    audit("runner.start", server_id=CFG.server_id, port=CFG.port, build_fingerprint_sha256=BUILD_FINGERPRINT, build_revision=BUILD_REVISION)
    ThreadingHTTPServer(("0.0.0.0", CFG.port), Handler).serve_forever()
