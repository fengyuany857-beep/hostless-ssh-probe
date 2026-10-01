from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import posixpath
import re
import shlex
import socket
import sqlite3
import stat
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import paramiko

RPC_VERSION = "vcw.runner.v1"
STATUSES = {"VERIFIED", "FAILED", "OUTCOME_UNKNOWN", "DENIED", "RATE_LIMITED"}
SIDE_EFFECTS = {"write_file", "apply_patch", "exec", "start_job", "cancel_job", "transfer"}
SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")


class PolicyError(ValueError):
    pass


class BackendTimeout(TimeoutError):
    pass


class BackendFailure(RuntimeError):
    pass


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _csv(name: str, default: str) -> frozenset[str]:
    return frozenset(x.strip() for x in os.environ.get(name, default).split(",") if x.strip())


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_host_key_sha256(value: str) -> str:
    value = value.strip()
    if value.lower().startswith("sha256:"):
        value = value.split(":", 1)[1]
    value = value.rstrip("=")
    if not re.fullmatch(r"[A-Za-z0-9+/]{43}", value):
        raise RuntimeError("SSH_HOST_KEY_SHA256 must be a SHA256 host-key fingerprint")
    return value


@dataclass(frozen=True)
class Config:
    runner_token: str
    server_id: str
    target_host: str
    target_port: int
    target_user: str
    project_root: str
    ssh_private_key: str
    ssh_host_key_sha256: str
    allowed_tools: frozenset[str]
    allowed_exec: frozenset[str]
    backend_timeout_s: float
    max_file_bytes: int
    max_output_bytes: int
    max_inflight: int
    state_db: str
    port: int

    @classmethod
    def from_env(cls) -> "Config":
        key = os.environ.get("SSH_PRIVATE_KEY", "")
        key_b64 = os.environ.get("SSH_PRIVATE_KEY_B64", "").strip()
        if not key and key_b64:
            key = base64.b64decode(key_b64).decode("utf-8")
        if not key.strip():
            raise RuntimeError("SSH_PRIVATE_KEY or SSH_PRIVATE_KEY_B64 is required")
        root = _required("VCW_PROJECT_ROOT")
        if not root.startswith("/"):
            raise RuntimeError("VCW_PROJECT_ROOT must be absolute")
        token = os.environ.get("RUNNER_TOKEN", os.environ.get("PROBE_TOKEN", "")).strip()
        if not token:
            raise RuntimeError("RUNNER_TOKEN is required")
        return cls(
            runner_token=token,
            server_id=_required("VCW_SERVER_ID"),
            target_host=_required("TARGET_HOST"),
            target_port=int(os.environ.get("TARGET_PORT", "22")),
            target_user=_required("TARGET_USER"),
            project_root=root.rstrip("/") or "/",
            ssh_private_key=key,
            ssh_host_key_sha256=normalize_host_key_sha256(_required("SSH_HOST_KEY_SHA256")),
            allowed_tools=_csv("VCW_ALLOWED_TOOLS", "read_file,write_file,apply_patch,exec,start_job,job_status,cancel_job,transfer,reconcile"),
            allowed_exec=_csv("VCW_ALLOWED_EXEC", "git,python,python3,pytest,node,npm,npx"),
            backend_timeout_s=float(os.environ.get("VCW_BACKEND_TIMEOUT_S", "20")),
            max_file_bytes=int(os.environ.get("VCW_MAX_FILE_BYTES", str(4 * 1024 * 1024))),
            max_output_bytes=int(os.environ.get("VCW_MAX_OUTPUT_BYTES", str(1024 * 1024))),
            max_inflight=max(1, int(os.environ.get("VCW_MAX_INFLIGHT", "4"))),
            state_db=os.environ.get("VCW_STATE_DB", "/tmp/vcw-runner.sqlite3"),
            port=int(os.environ.get("PORT", "8080")),
        )


@dataclass(frozen=True)
class Policy:
    root: str
    tools: frozenset[str]
    executables: frozenset[str]

    def check_request_id(self, value: object) -> str:
        if not isinstance(value, str) or not SAFE_ID.fullmatch(value):
            raise PolicyError("invalid request_id")
        return value

    def check_tool(self, value: object) -> str:
        if not isinstance(value, str) or value not in self.tools:
            raise PolicyError(f"tool not allowed: {value}")
        return value

    def path(self, value: object) -> str:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise PolicyError("invalid path")
        candidate = posixpath.normpath(value if value.startswith("/") else posixpath.join(self.root, value))
        if self.root != "/" and candidate != self.root and not candidate.startswith(self.root + "/"):
            raise PolicyError("path escapes project root")
        return candidate

    def cwd(self, value: object | None) -> str:
        return self.path(self.root if value in (None, "") else value)

    def argv(self, value: object) -> list[str]:
        if not isinstance(value, list) or not value or not all(isinstance(x, str) and x for x in value):
            raise PolicyError("argv must be a non-empty string array")
        if any("\x00" in x or "\n" in x or "\r" in x for x in value):
            raise PolicyError("argv contains forbidden control characters")
        exe = posixpath.basename(value[0])
        if exe not in self.executables:
            raise PolicyError(f"executable not allowed: {exe}")
        return list(value)

    def patch_paths(self, patch: object) -> list[str]:
        if not isinstance(patch, str) or not patch:
            raise PolicyError("patch must be non-empty text")
        touched: set[str] = set()
        for line in patch.splitlines():
            if not (line.startswith("+++ ") or line.startswith("--- ")):
                continue
            raw = line[4:].split("\t", 1)[0].strip()
            if raw == "/dev/null":
                continue
            if raw.startswith("a/") or raw.startswith("b/"):
                raw = raw[2:]
            normalized = posixpath.normpath(raw)
            if raw.startswith("/") or normalized in {"", ".", ".."} or normalized.startswith("../"):
                raise PolicyError("patch contains unsafe path")
            self.path(normalized)
            touched.add(normalized)
        if not touched:
            raise PolicyError("patch contains no file paths")
        return sorted(touched)


class OperationStore:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS operations (request_id TEXT PRIMARY KEY, method TEXT NOT NULL, state TEXT NOT NULL, response_json TEXT, updated_at REAL NOT NULL)")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def get(self, request_id: str) -> dict[str, Any] | None:
        with self.lock, self._connect() as conn:
            row = conn.execute("SELECT method,state,response_json,updated_at FROM operations WHERE request_id=?", (request_id,)).fetchone()
        if not row:
            return None
        return {"method": row[0], "state": row[1], "response": json.loads(row[2]) if row[2] else None, "updated_at": row[3]}

    def begin(self, request_id: str, method: str) -> dict[str, Any] | None:
        with self.lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT method,state,response_json,updated_at FROM operations WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row:
                if row[0] != method:
                    raise PolicyError("request_id already used for another method")
                return {
                    "method": row[0],
                    "state": row[1],
                    "response": json.loads(row[2]) if row[2] else None,
                    "updated_at": row[3],
                }
            conn.execute(
                "INSERT INTO operations(request_id,method,state,updated_at) VALUES(?,?,'RUNNING',?)",
                (request_id, method, time.time()),
            )
        return None

    def finish(self, request_id: str, status: str, response: dict[str, Any]) -> None:
        with self.lock, self._connect() as conn:
            conn.execute("UPDATE operations SET state=?, response_json=?, updated_at=? WHERE request_id=?", (status, json.dumps(response, separators=(",", ":"), sort_keys=True), time.time(), request_id))


class PinnedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected: str):
        self.expected = expected.rstrip("=")

    def missing_host_key(self, client, hostname, key):
        algorithm = key.get_name()
        got = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        if got != self.expected:
            raise paramiko.SSHException(
                f"host key mismatch for {hostname}: algorithm={algorithm} "
                f"got=SHA256:{got} expected=SHA256:{self.expected}"
            )
        client.get_host_keys().add(hostname, algorithm, key)


def load_private_key(text: str) -> paramiko.PKey:
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(text))
        except Exception:
            pass
    raise RuntimeError("unsupported or invalid SSH private key")


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str


class SSHBackend:
    def __init__(self, cfg: Config, policy: Policy):
        self.cfg = cfg
        self.policy = policy
        self.lock = threading.RLock()
        self.client: paramiko.SSHClient | None = None
        self.generation = 0

    def reset(self) -> None:
        with self.lock:
            if self.client:
                try:
                    self.client.close()
                except Exception:
                    pass
            self.client = None
            self.generation += 1

    def connect(self) -> paramiko.SSHClient:
        with self.lock:
            transport = self.client.get_transport() if self.client else None
            if transport and transport.is_active():
                return self.client
            self.reset()
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(PinnedHostKeyPolicy(self.cfg.ssh_host_key_sha256))
            client.connect(
                self.cfg.target_host,
                port=self.cfg.target_port,
                username=self.cfg.target_user,
                pkey=load_private_key(self.cfg.ssh_private_key),
                timeout=self.cfg.backend_timeout_s,
                banner_timeout=self.cfg.backend_timeout_s,
                auth_timeout=self.cfg.backend_timeout_s,
                allow_agent=False,
                look_for_keys=False,
            )
            self.client = client
            return client

    def probe(self) -> dict[str, Any]:
        t = self.connect().get_transport()
        return {"ok": bool(t and t.is_active()), "port": self.cfg.target_port, "connection_generation": self.generation}

    def canonical(self, sftp, path: str, allow_missing: bool = False) -> str:
        lexical = self.policy.path(path)
        try:
            canonical = sftp.normalize(lexical)
            self.policy.path(canonical)
            return canonical
        except OSError:
            if not allow_missing:
                raise
            parent = sftp.normalize(posixpath.dirname(lexical))
            self.policy.path(parent)
            return self.policy.path(posixpath.join(parent, posixpath.basename(lexical)))

    def read_bytes(self, path: str) -> bytes:
        with self.lock:
            try:
                with self.connect().open_sftp() as sftp:
                    remote = self.canonical(sftp, path)
                    attrs = sftp.lstat(remote)
                    if stat.S_ISLNK(attrs.st_mode):
                        remote = sftp.normalize(remote)
                        self.policy.path(remote)
                        attrs = sftp.stat(remote)
                    if attrs.st_size > self.cfg.max_file_bytes:
                        raise PolicyError("file exceeds VCW_MAX_FILE_BYTES")
                    with sftp.open(remote, "rb") as f:
                        data = f.read(self.cfg.max_file_bytes + 1)
                    if len(data) > self.cfg.max_file_bytes:
                        raise PolicyError("file exceeds VCW_MAX_FILE_BYTES")
                    return data
            except socket.timeout as exc:
                self.reset()
                raise BackendTimeout("SFTP read timed out") from exc

    def write_bytes_cas(self, path: str, data: bytes, expected_sha256: str | None) -> dict[str, Any]:
        if len(data) > self.cfg.max_file_bytes:
            raise PolicyError("payload exceeds VCW_MAX_FILE_BYTES")
        with self.lock:
            try:
                with self.connect().open_sftp() as sftp:
                    lexical = self.policy.path(path)
                    parent = sftp.normalize(posixpath.dirname(lexical))
                    self.policy.path(parent)
                    remote = self.policy.path(posixpath.join(parent, posixpath.basename(lexical)))
                    current_sha = None
                    try:
                        attrs = sftp.lstat(remote)
                        if stat.S_ISLNK(attrs.st_mode):
                            raise PolicyError("refusing to overwrite symlink")
                        with sftp.open(remote, "rb") as f:
                            current_sha = sha256(f.read(self.cfg.max_file_bytes + 1))
                    except FileNotFoundError:
                        pass
                    except OSError as exc:
                        if getattr(exc, "errno", None) != 2:
                            raise
                    if expected_sha256 is not None and current_sha != expected_sha256:
                        return {"ok": False, "code": "CAS_MISMATCH", "current_sha256": current_sha}
                    tmp = remote + f".vcw-tmp-{uuid.uuid4().hex}"
                    try:
                        with sftp.open(tmp, "wb") as f:
                            f.write(data)
                            f.flush()
                        sftp.posix_rename(tmp, remote)
                    except (AttributeError, OSError) as exc:
                        raise BackendFailure("atomic posix_rename is required") from exc
                    finally:
                        try:
                            sftp.remove(tmp)
                        except OSError:
                            pass
                    with sftp.open(remote, "rb") as f:
                        actual = sha256(f.read(self.cfg.max_file_bytes + 1))
                    desired = sha256(data)
                    if actual != desired:
                        raise BackendFailure("post-write SHA256 verification failed")
                    return {"ok": True, "sha256": actual, "previous_sha256": current_sha, "bytes": len(data)}
            except socket.timeout as exc:
                self.reset()
                raise BackendTimeout("SFTP write timed out") from exc

    def exec_argv(self, argv: list[str], cwd: str | None, timeout_s: float | None = None) -> ExecResult:
        argv = self.policy.argv(argv)
        cwd = self.policy.cwd(cwd)
        timeout = min(float(timeout_s or self.cfg.backend_timeout_s), 300.0)
        command = "cd -- {} && exec {}".format(shlex.quote(cwd), " ".join(shlex.quote(x) for x in argv))
        return self.internal_exec(command, timeout)

    def internal_exec(self, command: str, timeout_s: float | None = None) -> ExecResult:
        timeout = float(timeout_s or self.cfg.backend_timeout_s)
        with self.lock:
            try:
                _, stdout, stderr = self.connect().exec_command(command, timeout=timeout)
                stdout.channel.settimeout(timeout)
                code = stdout.channel.recv_exit_status()
                out = stdout.read(self.cfg.max_output_bytes + 1)
                err = stderr.read(self.cfg.max_output_bytes + 1)
                if len(out) > self.cfg.max_output_bytes or len(err) > self.cfg.max_output_bytes:
                    raise BackendFailure("command output exceeded VCW_MAX_OUTPUT_BYTES")
                return ExecResult(code, out.decode(errors="replace"), err.decode(errors="replace"))
            except socket.timeout as exc:
                self.reset()
                raise BackendTimeout("SSH exec timed out") from exc


class RunnerService:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.policy = Policy(cfg.project_root, cfg.allowed_tools, cfg.allowed_exec)
        self.backend = SSHBackend(cfg, self.policy)
        self.store = OperationStore(cfg.state_db)

    def response(self, request_id: str, status: str, result: dict[str, Any] | None = None, code: str | None = None, message: str | None = None) -> dict[str, Any]:
        if status not in STATUSES:
            raise ValueError(status)
        return {"rpc_version": RPC_VERSION, "request_id": request_id, "server_id": self.cfg.server_id, "connection_generation": self.backend.generation, "status": status, "result": result, "error": None if code is None else {"code": code, "message": message or code}}

    def dispatch(self, body: dict[str, Any]) -> dict[str, Any]:
        request_id = self.policy.check_request_id(body.get("request_id"))
        if body.get("server_id") != self.cfg.server_id:
            raise PolicyError("server_id mismatch")
        method = self.policy.check_tool(body.get("method"))
        params = body.get("params", {})
        if not isinstance(params, dict):
            raise PolicyError("params must be an object")
        if method in SIDE_EFFECTS:
            prior = self.store.begin(request_id, method)
            if prior and prior["response"] is not None:
                return prior["response"]
            if prior and prior["state"] == "RUNNING":
                return self.response(request_id, "OUTCOME_UNKNOWN", code="REQUEST_ALREADY_IN_FLIGHT", message="reconcile before retrying")
        try:
            result = getattr(self, f"rpc_{method}")(request_id, params)
        except PolicyError as exc:
            result = self.response(request_id, "DENIED", code="POLICY_DENIED", message=str(exc))
        except BackendTimeout as exc:
            result = self.response(request_id, "OUTCOME_UNKNOWN", code="BACKEND_TIMEOUT", message=str(exc))
        except BackendFailure as exc:
            result = self.response(request_id, "FAILED", code="BACKEND_FAILURE", message=str(exc))
        except Exception as exc:
            result = self.response(request_id, "FAILED", code=type(exc).__name__, message=str(exc))
        if method in SIDE_EFFECTS:
            self.store.finish(request_id, result["status"], result)
        return result

    def rpc_read_file(self, rid: str, p: dict[str, Any]) -> dict[str, Any]:
        path = self.policy.path(p.get("path"))
        data = self.backend.read_bytes(path)
        enc = p.get("encoding", "utf-8")
        if enc == "utf-8":
            content = data.decode("utf-8")
        elif enc == "base64":
            content = base64.b64encode(data).decode()
        else:
            raise PolicyError("encoding must be utf-8 or base64")
        return self.response(rid, "VERIFIED", {"path": path, "encoding": enc, "content": content, "sha256": sha256(data), "bytes": len(data)})

    def decode_content(self, p: dict[str, Any]) -> bytes:
        content = p.get("content")
        enc = p.get("encoding", "utf-8")
        if not isinstance(content, str):
            raise PolicyError("content must be a string")
        if enc == "utf-8":
            return content.encode()
        if enc == "base64":
            try:
                return base64.b64decode(content, validate=True)
            except Exception as exc:
                raise PolicyError("invalid base64 content") from exc
        raise PolicyError("encoding must be utf-8 or base64")

    def rpc_write_file(self, rid: str, p: dict[str, Any]) -> dict[str, Any]:
        path = self.policy.path(p.get("path"))
        data = self.decode_content(p)
        expected = p.get("expected_sha256")
        if expected is not None and (not isinstance(expected, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected)):
            raise PolicyError("expected_sha256 must be a SHA256 hex digest or null")
        result = self.backend.write_bytes_cas(path, data, expected.lower() if isinstance(expected, str) else None)
        if not result["ok"]:
            return self.response(rid, "FAILED", result, result["code"], "CAS precondition failed")
        return self.response(rid, "VERIFIED", {"path": path, **result})

    def rpc_exec(self, rid: str, p: dict[str, Any]) -> dict[str, Any]:
        argv = self.policy.argv(p.get("argv"))
        cwd = self.policy.cwd(p.get("cwd"))
        r = self.backend.exec_argv(argv, cwd, p.get("timeout_s"))
        status = "VERIFIED" if r.exit_code == 0 else "FAILED"
        return self.response(rid, status, {"argv": argv, "cwd": cwd, "exit_code": r.exit_code, "stdout": r.stdout, "stderr": r.stderr}, None if status == "VERIFIED" else "NONZERO_EXIT", None if status == "VERIFIED" else f"command exited {r.exit_code}")

    def rpc_apply_patch(self, rid: str, p: dict[str, Any]) -> dict[str, Any]:
        patch = p.get("patch")
        touched = self.policy.patch_paths(patch)
        data = patch.encode()
        rel = f".vcw-runner/tmp/{rid}.patch"
        remote = self.policy.path(rel)
        mk = self.backend.internal_exec("mkdir -p -- " + shlex.quote(posixpath.dirname(remote)))
        if mk.exit_code != 0:
            raise BackendFailure("cannot create patch temp directory")
        self.backend.write_bytes_cas(remote, data, None)
        check = self.backend.exec_argv(["git", "apply", "--check", rel], self.cfg.project_root)
        if check.exit_code != 0:
            return self.response(rid, "FAILED", {"touched": touched, "patch_sha256": sha256(data), "stderr": check.stderr}, "PATCH_CHECK_FAILED", "git apply --check failed")
        applied = self.backend.exec_argv(["git", "apply", "--whitespace=nowarn", rel], self.cfg.project_root)
        if applied.exit_code != 0:
            return self.response(rid, "OUTCOME_UNKNOWN", {"touched": touched, "patch_sha256": sha256(data), "stderr": applied.stderr}, "PATCH_APPLY_UNCERTAIN", "reconcile repository state")
        return self.response(rid, "VERIFIED", {"touched": touched, "patch_sha256": sha256(data)})

    def job_paths(self, job_id: object) -> dict[str, str]:
        if not isinstance(job_id, str) or not re.fullmatch(r"job_[A-Za-z0-9_-]{8,80}", job_id):
            raise PolicyError("invalid job_id")
        base = self.policy.path(f".vcw-runner/jobs/{job_id}")
        return {"base": base, "pid": base + "/pid", "exit": base + "/exit", "log": base + "/log", "cancelled": base + "/cancelled"}

    def rpc_start_job(self, rid: str, p: dict[str, Any]) -> dict[str, Any]:
        argv = self.policy.argv(p.get("argv"))
        cwd = self.policy.cwd(p.get("cwd"))
        job_id = "job_" + hashlib.sha256(rid.encode()).hexdigest()[:20]
        paths = self.job_paths(job_id)
        inner = "cd -- {} && {}; rc=$?; printf '%s\\n' \"$rc\" > {}; exit \"$rc\"".format(shlex.quote(cwd), " ".join(shlex.quote(x) for x in argv), shlex.quote(paths["exit"]))
        cmd = "mkdir -p -- {base} && if [ -f {pid} ]; then cat {pid}; else nohup setsid sh -c {inner} > {log} 2>&1 < /dev/null & pid=$!; printf '%s\\n' \"$pid\" > {pid}; printf '%s\\n' \"$pid\"; fi".format(base=shlex.quote(paths["base"]), pid=shlex.quote(paths["pid"]), inner=shlex.quote(inner), log=shlex.quote(paths["log"]))
        r = self.backend.internal_exec(cmd)
        pid = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
        if r.exit_code != 0 or not pid.isdigit():
            raise BackendFailure("failed to start remote job")
        return self.response(rid, "VERIFIED", {"job_id": job_id, "pid": int(pid), "state": "RUNNING", "argv": argv, "cwd": cwd})

    def rpc_job_status(self, rid: str, p: dict[str, Any]) -> dict[str, Any]:
        job_id = p.get("job_id")
        paths = self.job_paths(job_id)
        max_log = min(max(int(p.get("max_log_bytes", 32768)), 0), 131072)
        cmd = "if [ -f {exitf} ]; then printf 'EXIT '; cat {exitf}; elif [ -f {pid} ]; then pid=$(cat {pid}); if kill -0 \"$pid\" 2>/dev/null; then printf 'RUNNING\\n'; else printf 'UNKNOWN\\n'; fi; else printf 'MISSING\\n'; fi; printf '%s\\n' '---LOG---'; if [ -f {log} ]; then tail -c {n} {log}; fi".format(exitf=shlex.quote(paths["exit"]), pid=shlex.quote(paths["pid"]), log=shlex.quote(paths["log"]), n=max_log)
        r = self.backend.internal_exec(cmd)
        if r.exit_code != 0:
            raise BackendFailure("job status query failed")
        head, _, log = r.stdout.partition("---LOG---\n")
        state = head.strip()
        if state.startswith("EXIT "):
            code = int(state.split()[1])
            return self.response(rid, "VERIFIED", {"job_id": job_id, "state": "SUCCEEDED" if code == 0 else "FAILED", "exit_code": code, "log_tail": log})
        if state == "RUNNING":
            return self.response(rid, "VERIFIED", {"job_id": job_id, "state": "RUNNING", "log_tail": log})
        if state == "MISSING":
            return self.response(rid, "FAILED", {"job_id": job_id}, "JOB_NOT_FOUND", "job metadata not found")
        return self.response(rid, "OUTCOME_UNKNOWN", {"job_id": job_id, "state": "UNKNOWN", "log_tail": log}, "JOB_STATE_UNKNOWN", "pid disappeared without exit record")

    def rpc_cancel_job(self, rid: str, p: dict[str, Any]) -> dict[str, Any]:
        job_id = p.get("job_id")
        paths = self.job_paths(job_id)
        cmd = "test -f {pid} || exit 44; pid=$(cat {pid}); kill -TERM -- -\"$pid\" 2>/dev/null || true; sleep 2; kill -KILL -- -\"$pid\" 2>/dev/null || true; printf 'cancelled\\n' > {cancelled}".format(pid=shlex.quote(paths["pid"]), cancelled=shlex.quote(paths["cancelled"]))
        r = self.backend.internal_exec(cmd, max(5.0, self.cfg.backend_timeout_s))
        if r.exit_code == 44:
            return self.response(rid, "FAILED", None, "JOB_NOT_FOUND", "job metadata not found")
        if r.exit_code != 0:
            return self.response(rid, "OUTCOME_UNKNOWN", None, "CANCEL_UNCERTAIN", r.stderr[-500:])
        return self.response(rid, "VERIFIED", {"job_id": job_id, "state": "CANCELLED"})

    def rpc_transfer(self, rid: str, p: dict[str, Any]) -> dict[str, Any]:
        direction = p.get("direction")
        if direction == "upload":
            data = self.decode_content(p)
            content_sha = p.get("content_sha256")
            if content_sha is not None and sha256(data) != content_sha:
                raise PolicyError("content_sha256 does not match upload payload")
            path = self.policy.path(p.get("path"))
            result = self.backend.write_bytes_cas(path, data, p.get("expected_sha256"))
            if not result["ok"]:
                return self.response(rid, "FAILED", result, result["code"], "transfer CAS failed")
            return self.response(rid, "VERIFIED", {"direction": direction, "path": path, **result})
        if direction == "download":
            path = self.policy.path(p.get("path"))
            data = self.backend.read_bytes(path)
            return self.response(rid, "VERIFIED", {"direction": direction, "path": path, "encoding": "base64", "content": base64.b64encode(data).decode(), "sha256": sha256(data), "bytes": len(data)})
        raise PolicyError("transfer direction must be upload or download")

    def rpc_reconcile(self, rid: str, p: dict[str, Any]) -> dict[str, Any]:
        kind = p.get("kind")
        if kind == "request":
            target = p.get("target_request_id")
            if not isinstance(target, str):
                raise PolicyError("target_request_id is required")
            old = self.store.get(target)
            if not old:
                return self.response(rid, "OUTCOME_UNKNOWN", None, "REQUEST_NOT_FOUND", "no local request record")
            if old["response"]:
                observed = old["response"].get("status", "OUTCOME_UNKNOWN")
                if observed == "OUTCOME_UNKNOWN":
                    return self.response(
                        rid,
                        "OUTCOME_UNKNOWN",
                        {"target_request_id": target, "record": old},
                        "REQUEST_OUTCOME_UNKNOWN",
                        "stored request outcome is still unknown",
                    )
                return self.response(
                    rid,
                    "VERIFIED",
                    {"target_request_id": target, "observed_status": observed, "record": old},
                )
            return self.response(rid, "OUTCOME_UNKNOWN", {"target_request_id": target, "record": old}, "REQUEST_INCOMPLETE", "no terminal response")
        if kind == "file":
            path = self.policy.path(p.get("path"))
            expected = p.get("sha256")
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
                raise PolicyError("sha256 is required for file reconciliation")
            try:
                actual = sha256(self.backend.read_bytes(path))
            except FileNotFoundError:
                return self.response(rid, "FAILED", {"path": path, "exists": False}, "FILE_NOT_FOUND", "file does not exist")
            if actual == expected.lower():
                return self.response(rid, "VERIFIED", {"path": path, "actual_sha256": actual})
            return self.response(rid, "FAILED", {"path": path, "expected_sha256": expected.lower(), "actual_sha256": actual}, "SHA_MISMATCH", "file digest differs")
        if kind == "job":
            return self.rpc_job_status(rid, {"job_id": p.get("job_id"), "max_log_bytes": p.get("max_log_bytes", 32768)})
        raise PolicyError("reconcile kind must be request, file, or job")
