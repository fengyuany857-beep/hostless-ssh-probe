from __future__ import annotations

import base64
import hashlib
import io
import json
import math
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

from channel_exec import CommandOutputTooLarge, CommandTimeout, run_command_channel

RPC_VERSION = "vcw.runner.v1"
STATUSES = {"VERIFIED", "FAILED", "OUTCOME_UNKNOWN", "DENIED", "RATE_LIMITED"}
KNOWN_METHODS = frozenset({"read_file", "write_file", "apply_patch", "exec", "start_job", "job_status", "cancel_job", "transfer", "reconcile"})
SIDE_EFFECTS = {"write_file", "apply_patch", "exec", "start_job", "cancel_job"}
SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")


class PolicyError(ValueError):
    pass


class BackendTimeout(TimeoutError):
    pass


class BackendFailure(RuntimeError):
    pass


class BackendUncertain(RuntimeError):
    pass


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _csv(name: str, default: str) -> frozenset[str]:
    return frozenset(x.strip() for x in os.environ.get(name, default).split(",") if x.strip())


def _positive_finite_env(name: str, default: str, *, maximum: float | None = None) -> float:
    try:
        value = float(os.environ.get(name, default))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{name} must be a finite positive number") from exc
    if not math.isfinite(value) or value <= 0 or (maximum is not None and value > maximum):
        suffix = f" <= {maximum}" if maximum is not None else ""
        raise RuntimeError(f"{name} must be a finite positive number{suffix}")
    return value


def normalize_exec_path(value: str) -> str:
    entries = value.split(":")
    if not entries or any(not x or not x.startswith("/") or posixpath.normpath(x) != x for x in entries):
        raise RuntimeError("VCW_EXEC_PATH must be a colon-separated list of normalized absolute directories")
    return ":".join(entries)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_sha256_hex(value: object, field: str, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise PolicyError(f"{field} must be a SHA256 hex digest" + (" or null" if allow_none else ""))
    return value.lower()


def is_side_effect_request(method: str, params: dict[str, Any]) -> bool:
    return method in SIDE_EFFECTS or (method == "transfer" and params.get("direction") == "upload")


def correlate_response(response: dict[str, Any], session_id: str | None) -> dict[str, Any]:
    correlated = dict(response)
    if session_id is None:
        correlated.pop("session_id", None)
    else:
        correlated["session_id"] = session_id
    return correlated


def canonical_request_fingerprint(server_id: str, method: str, params: dict[str, Any]) -> str:
    try:
        raw = json.dumps(
            {"server_id": server_id, "method": method, "params": params},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PolicyError("request contains non-canonical JSON values") from exc
    return sha256(raw)


def normalize_host_key_sha256(value: str) -> str:
    value = value.strip()
    if value.lower().startswith("sha256:"):
        value = value.split(":", 1)[1]
    value = value.rstrip("=")
    if not re.fullmatch(r"[A-Za-z0-9+/]{43}", value):
        raise RuntimeError("SSH_HOST_KEY_SHA256 must be a SHA256 host-key fingerprint")
    try:
        decoded = base64.b64decode(value + "=", validate=True)
    except Exception as exc:
        raise RuntimeError("SSH_HOST_KEY_SHA256 must be a SHA256 host-key fingerprint") from exc
    if len(decoded) != 32:
        raise RuntimeError("SSH_HOST_KEY_SHA256 must decode to 32 bytes")
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
    exec_path: str
    backend_timeout_s: float
    max_file_bytes: int
    max_output_bytes: int
    max_inflight: int
    ledger_db: str
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
        if not root.startswith("/") or posixpath.normpath(root) != root or root == "/":
            raise RuntimeError("VCW_PROJECT_ROOT must be a normalized absolute non-root path")
        target_user = _required("TARGET_USER")
        if target_user == "root":
            raise RuntimeError("TARGET_USER=root is forbidden; use a dedicated least-privileged account")
        token = os.environ.get("RUNNER_TOKEN", "").strip()
        if not token:
            raise RuntimeError("RUNNER_TOKEN is required")
        if len(token) < 32:
            raise RuntimeError("RUNNER_TOKEN must be at least 32 characters")
        server_id = _required("VCW_SERVER_ID")
        if not SAFE_ID.fullmatch(server_id):
            raise RuntimeError("VCW_SERVER_ID must match the RPC safe-id syntax")
        target_port = int(os.environ.get("TARGET_PORT", "22"))
        port = int(os.environ.get("PORT", "8080"))
        if not 1 <= target_port <= 65535:
            raise RuntimeError("TARGET_PORT must be between 1 and 65535")
        if not 1 <= port <= 65535:
            raise RuntimeError("PORT must be between 1 and 65535")
        max_file_bytes = int(os.environ.get("VCW_MAX_FILE_BYTES", str(4 * 1024 * 1024)))
        max_output_bytes = int(os.environ.get("VCW_MAX_OUTPUT_BYTES", str(1024 * 1024)))
        max_inflight = int(os.environ.get("VCW_MAX_INFLIGHT", "4"))
        if max_file_bytes <= 0 or max_output_bytes <= 0:
            raise RuntimeError("VCW_MAX_FILE_BYTES and VCW_MAX_OUTPUT_BYTES must be positive")
        if not 1 <= max_inflight <= 128:
            raise RuntimeError("VCW_MAX_INFLIGHT must be between 1 and 128")
        cfg = cls(
            runner_token=token,
            server_id=server_id,
            target_host=_required("TARGET_HOST"),
            target_port=target_port,
            target_user=target_user,
            project_root=root,
            ssh_private_key=key,
            ssh_host_key_sha256=normalize_host_key_sha256(_required("SSH_HOST_KEY_SHA256")),
            allowed_tools=_csv("VCW_ALLOWED_TOOLS", "read_file,write_file,apply_patch,exec,start_job,job_status,cancel_job,transfer,reconcile"),
            allowed_exec=_csv("VCW_ALLOWED_EXEC", "git,python,python3,pytest,node,npm,npx"),
            exec_path=normalize_exec_path(os.environ.get("VCW_EXEC_PATH", "/usr/local/bin:/usr/bin:/bin")),
            backend_timeout_s=_positive_finite_env("VCW_BACKEND_TIMEOUT_S", "20", maximum=300.0),
            max_file_bytes=max_file_bytes,
            max_output_bytes=max_output_bytes,
            max_inflight=max_inflight,
            ledger_db=os.environ.get("VCW_LEDGER_DATABASE_URL", "").strip() or os.environ.get("VCW_LEDGER_DB", "/tmp/vcw-runner-ledger.sqlite3"),
            port=port,
        )
        if not cfg.allowed_tools or not cfg.allowed_tools.issubset(KNOWN_METHODS):
            unknown = sorted(cfg.allowed_tools - KNOWN_METHODS)
            raise RuntimeError(f"VCW_ALLOWED_TOOLS contains unsupported v1 methods: {','.join(unknown)}")
        if not cfg.allowed_exec or any(posixpath.basename(x) != x or not x for x in cfg.allowed_exec):
            raise RuntimeError("VCW_ALLOWED_EXEC must contain bare executable names only")
        return cfg


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

    def check_session_id(self, value: object | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not SAFE_ID.fullmatch(value):
            raise PolicyError("invalid session_id")
        return value

    def check_job_id(self, value: object) -> str:
        if not isinstance(value, str) or not re.fullmatch(r"job_[A-Za-z0-9_-]{8,80}", value):
            raise PolicyError("invalid job_id")
        return value

    def timeout(self, value: object | None) -> float:
        if value is None:
            raise PolicyError("timeout_s is required when validating an explicit timeout")
        if isinstance(value, bool):
            raise PolicyError("timeout_s must be a finite positive number")
        try:
            timeout = float(value)
        except (TypeError, ValueError) as exc:
            raise PolicyError("timeout_s must be a finite positive number") from exc
        if not math.isfinite(timeout) or timeout <= 0:
            raise PolicyError("timeout_s must be a finite positive number")
        return min(timeout, 300.0)

    def params(self, method: str, value: object) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise PolicyError("params must be an object")

        fixed: dict[str, tuple[set[str], set[str]]] = {
            "read_file": ({"path", "encoding"}, {"path"}),
            "write_file": ({"path", "content", "encoding", "expected_sha256"}, {"path", "content"}),
            "apply_patch": ({"patch"}, {"patch"}),
            "exec": ({"argv", "cwd", "timeout_s"}, {"argv"}),
            "start_job": ({"argv", "cwd"}, {"argv"}),
            "job_status": ({"job_id", "max_log_bytes"}, {"job_id"}),
            "cancel_job": ({"job_id"}, {"job_id"}),
        }
        if method in fixed:
            allowed, required = fixed[method]
        elif method == "transfer":
            direction = value.get("direction")
            if direction == "upload":
                allowed = {"direction", "path", "content", "encoding", "content_sha256", "expected_sha256"}
                required = {"direction", "path", "content"}
            elif direction == "download":
                allowed = {"direction", "path"}
                required = {"direction", "path"}
            else:
                allowed = {"direction", "path"}
                required = {"direction", "path"}
        elif method == "reconcile":
            kind = value.get("kind")
            if kind == "request":
                allowed = {"kind", "target_request_id"}
                required = {"kind", "target_request_id"}
            elif kind == "file":
                allowed = {"kind", "path", "sha256"}
                required = {"kind", "path", "sha256"}
            elif kind == "job":
                allowed = {"kind", "job_id", "max_log_bytes"}
                required = {"kind", "job_id"}
            else:
                allowed = {"kind"}
                required = {"kind"}
        else:
            raise PolicyError(f"tool not allowed: {method}")

        extra = sorted(set(value) - allowed)
        if extra:
            raise PolicyError(f"unsupported params for {method}: {','.join(extra)}")
        missing = sorted(required - set(value))
        if missing:
            raise PolicyError(f"missing required params for {method}: {','.join(missing)}")

        if method in {"exec", "start_job"}:
            self.argv(value.get("argv"))
        if method in {"job_status", "cancel_job"}:
            self.check_job_id(value.get("job_id"))
        if method == "reconcile":
            kind = value.get("kind")
            if kind == "request":
                self.check_request_id(value.get("target_request_id"))
            elif kind == "job":
                self.check_job_id(value.get("job_id"))
        return value

    def path(self, value: object) -> str:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise PolicyError("invalid path")
        candidate = posixpath.normpath(value if value.startswith("/") else posixpath.join(self.root, value))
        if self.root != "/" and candidate != self.root and not candidate.startswith(self.root + "/"):
            raise PolicyError("path escapes project root")
        return candidate

    def user_path(self, value: object) -> str:
        resolved = self.path(value)
        rel = posixpath.relpath(resolved, self.root)
        if rel in {".git", ".vcw-runner"} or rel.startswith(".git/") or rel.startswith(".vcw-runner/"):
            raise PolicyError("path targets Runner/Git control metadata")
        return resolved

    def cwd(self, value: object | None) -> str:
        return self.user_path(self.root if value in (None, "") else value)

    def argv(self, value: object) -> list[str]:
        if not isinstance(value, list) or not value or not all(isinstance(x, str) and x for x in value):
            raise PolicyError("argv must be a non-empty string array")
        if any("\x00" in x or "\n" in x or "\r" in x for x in value):
            raise PolicyError("argv contains forbidden control characters")
        exe = posixpath.basename(value[0])
        if value[0] != exe:
            raise PolicyError("argv[0] must be a bare executable name, not a path")
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
            self.user_path(normalized)
            touched.add(normalized)
        if not touched:
            raise PolicyError("patch contains no file paths")
        return sorted(touched)


class IdempotencyLedger:
    POSTGRES_PREFIXES = ("postgresql://", "postgres://")
    TABLE = "vcw_runner_idempotency_v1"

    def __init__(self, target: str):
        self.target = target
        self.lock = threading.Lock()
        self.backend = "postgresql" if target.startswith(self.POSTGRES_PREFIXES) else "sqlite"
        self.durable = self.backend == "postgresql"
        self._psycopg = None

        if self.backend == "postgresql":
            try:
                import psycopg
            except ImportError as exc:
                raise RuntimeError("psycopg is required for VCW_LEDGER_DATABASE_URL") from exc
            self._psycopg = psycopg
            with self._pg_connect() as conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS vcw_runner_idempotency_v1 ("
                    "request_id TEXT PRIMARY KEY,"
                    "method TEXT NOT NULL,"
                    "state TEXT NOT NULL,"
                    "response_json TEXT,"
                    "updated_at DOUBLE PRECISION NOT NULL,"
                    "request_fingerprint TEXT,"
                    "reconcile_json TEXT"
                    ")"
                )
                conn.execute("ALTER TABLE vcw_runner_idempotency_v1 ADD COLUMN IF NOT EXISTS request_fingerprint TEXT")
                conn.execute("ALTER TABLE vcw_runner_idempotency_v1 ADD COLUMN IF NOT EXISTS reconcile_json TEXT")
        else:
            Path(target).parent.mkdir(parents=True, exist_ok=True)
            with self._sqlite_connect() as conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS vcw_runner_idempotency_v1 ("
                    "request_id TEXT PRIMARY KEY,"
                    "method TEXT NOT NULL,"
                    "state TEXT NOT NULL,"
                    "response_json TEXT,"
                    "updated_at REAL NOT NULL,"
                    "request_fingerprint TEXT,"
                    "reconcile_json TEXT"
                    ")"
                )
                columns = {row[1] for row in conn.execute("PRAGMA table_info(vcw_runner_idempotency_v1)")}
                if "request_fingerprint" not in columns:
                    conn.execute("ALTER TABLE vcw_runner_idempotency_v1 ADD COLUMN request_fingerprint TEXT")
                if "reconcile_json" not in columns:
                    conn.execute("ALTER TABLE vcw_runner_idempotency_v1 ADD COLUMN reconcile_json TEXT")

    def _sqlite_connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.target, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _pg_connect(self):
        assert self._psycopg is not None
        return self._psycopg.connect(
            self.target,
            connect_timeout=5,
            prepare_threshold=None,
            autocommit=True,
            options="-c lock_timeout=5000 -c statement_timeout=10000",
            application_name="vcw_remote_runner",
        )

    @staticmethod
    def _record(row) -> dict[str, Any] | None:
        if not row:
            return None
        return {
            "method": row[0],
            "state": row[1],
            "response": json.loads(row[2]) if row[2] else None,
            "updated_at": row[3],
            "request_fingerprint": row[4],
            "reconcile_hint": json.loads(row[5]) if row[5] else None,
        }

    def get(self, request_id: str) -> dict[str, Any] | None:
        if self.backend == "postgresql":
            with self._pg_connect() as conn:
                row = conn.execute(
                    "SELECT method,state,response_json,updated_at,request_fingerprint,reconcile_json "
                    "FROM vcw_runner_idempotency_v1 WHERE request_id=%s",
                    (request_id,),
                ).fetchone()
            return self._record(row)

        with self.lock, self._sqlite_connect() as conn:
            row = conn.execute(
                "SELECT method,state,response_json,updated_at,request_fingerprint,reconcile_json "
                "FROM vcw_runner_idempotency_v1 WHERE request_id=?",
                (request_id,),
            ).fetchone()
        return self._record(row)

    def begin(self, request_id: str, method: str, request_fingerprint: str, reconcile_hint: dict[str, Any] | None = None) -> dict[str, Any] | None:
        now = time.time()
        reconcile_json = None if reconcile_hint is None else json.dumps(reconcile_hint, separators=(",", ":"), sort_keys=True)

        if self.backend == "postgresql":
            with self._pg_connect() as conn:
                inserted = conn.execute(
                    "INSERT INTO vcw_runner_idempotency_v1(request_id,method,state,updated_at,request_fingerprint,reconcile_json) "
                    "VALUES(%s,%s,'RUNNING',%s,%s,%s) "
                    "ON CONFLICT (request_id) DO NOTHING "
                    "RETURNING request_id",
                    (request_id, method, now, request_fingerprint, reconcile_json),
                ).fetchone()
                if inserted:
                    return None

                row = conn.execute(
                    "SELECT method,state,response_json,updated_at,request_fingerprint,reconcile_json "
                    "FROM vcw_runner_idempotency_v1 WHERE request_id=%s",
                    (request_id,),
                ).fetchone()
                if not row:
                    raise RuntimeError("operation ledger conflict without visible row")
                record = self._record(row)
                assert record is not None
                if record["method"] != method:
                    raise PolicyError("request_id already used for another method")
                if record["request_fingerprint"] is None:
                    raise PolicyError("request_id refers to a legacy record without request fingerprint; reconcile only")
                if record["request_fingerprint"] != request_fingerprint:
                    raise PolicyError("request_id already used for different request parameters")
                return record

        with self.lock, self._sqlite_connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT method,state,response_json,updated_at,request_fingerprint,reconcile_json "
                "FROM vcw_runner_idempotency_v1 WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row:
                record = self._record(row)
                assert record is not None
                if record["method"] != method:
                    raise PolicyError("request_id already used for another method")
                if record["request_fingerprint"] is None:
                    raise PolicyError("request_id refers to a legacy record without request fingerprint; reconcile only")
                if record["request_fingerprint"] != request_fingerprint:
                    raise PolicyError("request_id already used for different request parameters")
                return record
            conn.execute(
                "INSERT INTO vcw_runner_idempotency_v1(request_id,method,state,updated_at,request_fingerprint,reconcile_json) "
                "VALUES(?,?,'RUNNING',?,?,?)",
                (request_id, method, now, request_fingerprint, reconcile_json),
            )
        return None

    def finish(self, request_id: str, status: str, response: dict[str, Any]) -> None:
        payload = json.dumps(response, separators=(",", ":"), sort_keys=True)
        now = time.time()

        if self.backend == "postgresql":
            with self._pg_connect() as conn:
                cur = conn.execute(
                    "UPDATE vcw_runner_idempotency_v1 SET state=%s,response_json=%s,updated_at=%s "
                    "WHERE request_id=%s AND state='RUNNING'",
                    (status, payload, now, request_id),
                )
                if cur.rowcount != 1:
                    raise RuntimeError("operation ledger terminal update affected no row")
            return

        with self.lock, self._sqlite_connect() as conn:
            cur = conn.execute(
                "UPDATE vcw_runner_idempotency_v1 SET state=?,response_json=?,updated_at=? "
                "WHERE request_id=? AND state='RUNNING'",
                (status, payload, now, request_id),
            )
            if cur.rowcount != 1:
                raise RuntimeError("operation ledger terminal update affected no row")


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
            self.generation += 1
            return client

    def probe(self) -> dict[str, Any]:
        t = self.connect().get_transport()
        return {"ok": bool(t and t.is_active()), "port": self.cfg.target_port, "connection_generation": self.generation}

    def canonical(self, sftp, path: str, allow_missing: bool = False, allow_control: bool = False) -> str:
        validate = self.policy.path if allow_control else self.policy.user_path
        lexical = validate(path)
        try:
            canonical = sftp.normalize(lexical)
            return validate(canonical)
        except OSError:
            if not allow_missing:
                raise
            parent = validate(sftp.normalize(posixpath.dirname(lexical)))
            return validate(posixpath.join(parent, posixpath.basename(lexical)))

    def canonical_existing_path(self, path: str) -> str:
        with self.lock:
            try:
                with self.connect().open_sftp() as sftp:
                    return self.canonical(sftp, path)
            except socket.timeout as exc:
                self.reset()
                raise BackendTimeout("SFTP path resolution timed out") from exc

    def canonical_user_target(self, path: str) -> str:
        with self.lock:
            try:
                with self.connect().open_sftp() as sftp:
                    return self.canonical(sftp, path, allow_missing=True)
            except socket.timeout as exc:
                self.reset()
                raise BackendTimeout("SFTP path resolution timed out") from exc

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

    def write_bytes_cas(self, path: str, data: bytes, expected_sha256: str | None, *, allow_control: bool = False) -> dict[str, Any]:
        if len(data) > self.cfg.max_file_bytes:
            raise PolicyError("payload exceeds VCW_MAX_FILE_BYTES")
        with self.lock:
            rename_attempted = False
            try:
                with self.connect().open_sftp() as sftp:
                    validate = self.policy.path if allow_control else self.policy.user_path
                    lexical = validate(path)
                    parent = validate(sftp.normalize(posixpath.dirname(lexical)))
                    remote = validate(posixpath.join(parent, posixpath.basename(lexical)))
                    current_sha = None
                    current_mode = None
                    try:
                        attrs = sftp.lstat(remote)
                        if stat.S_ISLNK(attrs.st_mode):
                            raise PolicyError("refusing to overwrite symlink")
                        if not stat.S_ISREG(attrs.st_mode):
                            raise PolicyError("refusing to overwrite non-regular file")
                        if attrs.st_size > self.cfg.max_file_bytes:
                            raise PolicyError("existing file exceeds VCW_MAX_FILE_BYTES")
                        current_mode = stat.S_IMODE(attrs.st_mode)
                        with sftp.open(remote, "rb") as f:
                            current = f.read(self.cfg.max_file_bytes + 1)
                        if len(current) > self.cfg.max_file_bytes:
                            raise PolicyError("existing file exceeds VCW_MAX_FILE_BYTES")
                        current_sha = sha256(current)
                    except FileNotFoundError:
                        pass
                    except OSError as exc:
                        if getattr(exc, "errno", None) != 2:
                            raise

                    if expected_sha256 is not None and current_sha != expected_sha256:
                        return {"ok": False, "code": "CAS_MISMATCH", "current_sha256": current_sha}

                    desired_mode = current_mode if current_mode is not None else 0o644
                    tmp = remote + f".vcw-tmp-{uuid.uuid4().hex}"
                    try:
                        try:
                            with sftp.open(tmp, "wb") as f:
                                f.write(data)
                                f.flush()
                            sftp.chmod(tmp, desired_mode)
                        except (OSError, EOFError, paramiko.SSHException) as exc:
                            raise BackendFailure("failed to stage write before target rename") from exc

                        rename_attempted = True
                        try:
                            sftp.posix_rename(tmp, remote)
                        except AttributeError as exc:
                            rename_attempted = False
                            raise BackendFailure("atomic posix_rename is required") from exc
                        except OSError as exc:
                            raise BackendUncertain("atomic rename outcome is unknown; reconcile target file") from exc
                    finally:
                        try:
                            sftp.remove(tmp)
                        except OSError:
                            pass

                    try:
                        final_attrs = sftp.lstat(remote)
                        if not stat.S_ISREG(final_attrs.st_mode):
                            raise BackendUncertain("post-write target is not a regular file")
                        with sftp.open(remote, "rb") as f:
                            actual_data = f.read(self.cfg.max_file_bytes + 1)
                    except BackendUncertain:
                        raise
                    except Exception as exc:
                        raise BackendUncertain("write may be applied but readback failed; reconcile target file") from exc

                    if len(actual_data) > self.cfg.max_file_bytes:
                        raise BackendUncertain("write target exceeds verification bound after rename")
                    actual = sha256(actual_data)
                    desired = sha256(data)
                    actual_mode = stat.S_IMODE(final_attrs.st_mode)
                    if actual != desired:
                        raise BackendUncertain("post-write SHA256 verification failed; reconcile target file")
                    if actual_mode != desired_mode:
                        raise BackendUncertain("post-write file mode verification failed; reconcile target file")
                    return {
                        "ok": True,
                        "sha256": actual,
                        "previous_sha256": current_sha,
                        "bytes": len(data),
                        "mode": format(actual_mode, "04o"),
                    }
            except socket.timeout as exc:
                self.reset()
                raise BackendTimeout("SFTP write timed out") from exc
            except BackendUncertain:
                self.reset()
                raise
            except (EOFError, paramiko.SSHException) as exc:
                self.reset()
                if rename_attempted:
                    raise BackendUncertain("SSH/SFTP connection failed after rename began; reconcile target file") from exc
                raise BackendFailure("SSH/SFTP write failed before target rename") from exc

    def internal_exec(self, command: str, timeout_s: float | None = None) -> ExecResult:
        timeout = float(timeout_s or self.cfg.backend_timeout_s)
        runtime_home = self.policy.path(".vcw-runner/runtime-home")
        cache_home = posixpath.join(runtime_home, ".cache")
        npm_cache = posixpath.join(runtime_home, ".npm")
        command = (
            "umask 077; "
            "mkdir -p -- {home} {cache} {npm}; "
            "HOME={home}; XDG_CACHE_HOME={cache}; NPM_CONFIG_CACHE={npm}; PATH={path}; "
            "export HOME XDG_CACHE_HOME NPM_CONFIG_CACHE PATH; "
            "{command}"
        ).format(
            home=shlex.quote(runtime_home),
            cache=shlex.quote(cache_home),
            npm=shlex.quote(npm_cache),
            path=shlex.quote(self.cfg.exec_path),
            command=command,
        )
        with self.lock:
            try:
                code, out, err = run_command_channel(
                    self.connect(),
                    command,
                    command_timeout_s=timeout,
                    open_timeout_s=self.cfg.backend_timeout_s,
                    max_output_bytes=self.cfg.max_output_bytes,
                )
                return ExecResult(code, out.decode(errors="replace"), err.decode(errors="replace"))
            except CommandTimeout as exc:
                self.reset()
                raise BackendTimeout(str(exc)) from exc
            except CommandOutputTooLarge as exc:
                self.reset()
                raise BackendUncertain(f"{exc}; remote command outcome is unknown") from exc
            except socket.timeout as exc:
                self.reset()
                raise BackendTimeout("SSH command transport timed out") from exc
            except (EOFError, OSError, paramiko.SSHException) as exc:
                self.reset()
                raise BackendUncertain(
                    f"SSH command transport failed ({type(exc).__name__}); remote command outcome is unknown"
                ) from exc

    def exec_argv(self, argv: list[str], cwd: str | None, timeout_s: float | None = None) -> ExecResult:
        argv = self.policy.argv(argv)
        cwd = self.canonical_existing_path(self.policy.cwd(cwd))
        timeout = self.cfg.backend_timeout_s if timeout_s is None else self.policy.timeout(timeout_s)
        command = "cd -- {} && exec {}".format(
            shlex.quote(cwd),
            " ".join(shlex.quote(x) for x in argv),
        )
        return self.internal_exec(command, timeout)


class RunnerService:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.policy = Policy(cfg.project_root, cfg.allowed_tools, cfg.allowed_exec)
        self.backend = SSHBackend(cfg, self.policy)
        self.ledger = IdempotencyLedger(cfg.ledger_db)

    def response(self, request_id: str, status: str, result: dict[str, Any] | None = None, code: str | None = None, message: str | None = None) -> dict[str, Any]:
        if status not in STATUSES:
            raise ValueError(status)
        return {"rpc_version": RPC_VERSION, "request_id": request_id, "server_id": self.cfg.server_id, "connection_generation": self.backend.generation, "status": status, "result": result, "error": None if code is None else {"code": code, "message": message or code}}

    def reconciliation_hint(self, method: str, params: dict[str, Any], request_id: str) -> dict[str, Any] | None:
        if method == "write_file":
            path = self.policy.user_path(params.get("path"))
            data = self.decode_content(params)
            return {"kind": "file", "path": path, "sha256": sha256(data)}
        if method == "transfer" and params.get("direction") == "upload":
            path = self.policy.user_path(params.get("path"))
            data = self.decode_content(params)
            return {"kind": "file", "path": path, "sha256": sha256(data)}
        if method == "start_job":
            return {"kind": "job", "job_id": "job_" + hashlib.sha256(request_id.encode()).hexdigest()[:20]}
        if method == "cancel_job":
            return {"kind": "job", "job_id": self.policy.check_job_id(params.get("job_id"))}
        if method == "apply_patch":
            patch = params.get("patch")
            touched = self.policy.patch_paths(patch)
            return {"kind": "patch", "touched": touched, "patch_sha256": sha256(patch.encode())}
        return None

    def dispatch(self, body: dict[str, Any]) -> dict[str, Any]:
        allowed_envelope = {"server_id", "request_id", "session_id", "method", "params"}
        extra_envelope = sorted(set(body) - allowed_envelope)
        if extra_envelope:
            raise PolicyError(f"unsupported RPC envelope fields: {','.join(extra_envelope)}")
        request_id = self.policy.check_request_id(body.get("request_id"))
        if body.get("server_id") != self.cfg.server_id:
            raise PolicyError("server_id mismatch")
        session_id = self.policy.check_session_id(body.get("session_id"))
        method = self.policy.check_tool(body.get("method"))
        params = self.policy.params(method, body.get("params"))
        fingerprint = canonical_request_fingerprint(self.cfg.server_id, method, params)
        has_side_effect = is_side_effect_request(method, params)
        reconcile_hint = self.reconciliation_hint(method, params, request_id) if has_side_effect else None
        if has_side_effect:
            try:
                prior = self.ledger.begin(request_id, method, fingerprint, reconcile_hint)
            except PolicyError:
                raise
            except Exception as exc:
                unavailable = self.response(
                    request_id,
                    "FAILED",
                    None,
                    "LEDGER_UNAVAILABLE",
                    f"idempotency ledger unavailable before execution: {type(exc).__name__}",
                )
                return correlate_response(unavailable, session_id)
            if prior:
                if prior["response"] is not None:
                    return correlate_response(prior["response"], session_id)
                code = "REQUEST_ALREADY_IN_FLIGHT" if prior["state"] == "RUNNING" else "REQUEST_INCOMPLETE"
                message = "reconcile before retrying" if prior["state"] == "RUNNING" else "existing request record has no terminal response"
                incomplete = self.response(
                    request_id,
                    "OUTCOME_UNKNOWN",
                    {
                        "stored_state": prior["state"],
                        "reconcile_hint": prior.get("reconcile_hint"),
                    },
                    code=code,
                    message=message,
                )
                return correlate_response(incomplete, session_id)
        try:
            result = getattr(self, f"rpc_{method}")(request_id, params)
        except PolicyError as exc:
            result = self.response(request_id, "DENIED", code="POLICY_DENIED", message=str(exc))
        except BackendTimeout as exc:
            result = self.response(
                request_id,
                "OUTCOME_UNKNOWN",
                {"reconcile_hint": reconcile_hint} if reconcile_hint is not None else None,
                code="BACKEND_TIMEOUT",
                message=str(exc),
            )
        except BackendUncertain as exc:
            result = self.response(
                request_id,
                "OUTCOME_UNKNOWN",
                {"reconcile_hint": reconcile_hint} if reconcile_hint is not None else None,
                code="BACKEND_OUTCOME_UNKNOWN",
                message=str(exc),
            )
        except BackendFailure as exc:
            result = self.response(request_id, "FAILED", code="BACKEND_FAILURE", message=str(exc))
        except Exception as exc:
            result = self.response(request_id, "FAILED", code=type(exc).__name__, message=str(exc))
        if has_side_effect:
            try:
                self.ledger.finish(request_id, result["status"], result)
            except Exception as exc:
                uncertain = self.response(
                    request_id,
                    "OUTCOME_UNKNOWN",
                    {
                        "observed_action_status": result.get("status"),
                        "observed_action_result": result.get("result"),
                    },
                    "LEDGER_COMMIT_FAILED",
                    f"action returned but idempotency ledger terminal commit failed: {type(exc).__name__}",
                )
                return correlate_response(uncertain, session_id)
        return correlate_response(result, session_id)

    def rpc_read_file(self, rid: str, p: dict[str, Any]) -> dict[str, Any]:
        path = self.policy.user_path(p.get("path"))
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
        path = self.policy.user_path(p.get("path"))
        data = self.decode_content(p)
        expected = normalize_sha256_hex(p.get("expected_sha256"), "expected_sha256", allow_none=True)
        result = self.backend.write_bytes_cas(path, data, expected)
        if not result["ok"]:
            return self.response(rid, "FAILED", result, result["code"], "CAS precondition failed")
        return self.response(rid, "VERIFIED", {"path": path, **result})

    def rpc_exec(self, rid: str, p: dict[str, Any]) -> dict[str, Any]:
        argv = self.policy.argv(p.get("argv"))
        cwd = self.backend.canonical_existing_path(self.policy.cwd(p.get("cwd")))
        r = self.backend.exec_argv(argv, cwd, p.get("timeout_s"))
        status = "VERIFIED" if r.exit_code == 0 else "FAILED"
        return self.response(rid, status, {"argv": argv, "cwd": cwd, "exit_code": r.exit_code, "stdout": r.stdout, "stderr": r.stderr}, None if status == "VERIFIED" else "NONZERO_EXIT", None if status == "VERIFIED" else f"command exited {r.exit_code}")

    def rpc_apply_patch(self, rid: str, p: dict[str, Any]) -> dict[str, Any]:
        patch = p.get("patch")
        touched = self.policy.patch_paths(patch)
        for touched_path in touched:
            self.backend.canonical_user_target(touched_path)
        data = patch.encode()
        rel = f".vcw-runner/tmp/{rid}.patch"
        remote = self.policy.path(rel)
        mk = self.backend.internal_exec("mkdir -p -- " + shlex.quote(posixpath.dirname(remote)))
        if mk.exit_code != 0:
            raise BackendFailure("cannot create patch temp directory")

        try:
            self.backend.write_bytes_cas(remote, data, None, allow_control=True)
            check = self.backend.exec_argv(["git", "apply", "--check", rel], self.cfg.project_root)
            if check.exit_code != 0:
                return self.response(
                    rid,
                    "FAILED",
                    {"touched": touched, "patch_sha256": sha256(data), "stderr": check.stderr},
                    "PATCH_CHECK_FAILED",
                    "git apply --check failed",
                )

            applied = self.backend.exec_argv(["git", "apply", "--whitespace=nowarn", rel], self.cfg.project_root)
            if applied.exit_code != 0:
                return self.response(
                    rid,
                    "OUTCOME_UNKNOWN",
                    {"touched": touched, "patch_sha256": sha256(data), "stderr": applied.stderr},
                    "PATCH_APPLY_UNCERTAIN",
                    "reconcile repository state",
                )

            verify = self.backend.exec_argv(["git", "apply", "--reverse", "--check", rel], self.cfg.project_root)
            if verify.exit_code != 0:
                return self.response(
                    rid,
                    "OUTCOME_UNKNOWN",
                    {"touched": touched, "patch_sha256": sha256(data), "stderr": verify.stderr},
                    "PATCH_POSTCONDITION_UNVERIFIED",
                    "patch command returned success but reverse-check could not verify the applied post-condition",
                )

            return self.response(
                rid,
                "VERIFIED",
                {"touched": touched, "patch_sha256": sha256(data), "postcondition": "reverse_apply_check"},
            )
        finally:
            try:
                self.backend.internal_exec("rm -f -- " + shlex.quote(remote), min(5.0, self.cfg.backend_timeout_s))
            except Exception:
                pass

    def job_paths(self, job_id: object) -> dict[str, str]:
        job_id = self.policy.check_job_id(job_id)
        base = self.policy.path(f".vcw-runner/jobs/{job_id}")
        return {
            "base": base,
            "pid": base + "/pid",
            "start_ticks": base + "/start_ticks",
            "boot_id": base + "/boot_id",
            "exit": base + "/exit",
            "log": base + "/log",
            "cancelled": base + "/cancelled",
        }

    def rpc_start_job(self, rid: str, p: dict[str, Any]) -> dict[str, Any]:
        argv = self.policy.argv(p.get("argv"))
        cwd = self.backend.canonical_existing_path(self.policy.cwd(p.get("cwd")))
        job_id = "job_" + hashlib.sha256(rid.encode()).hexdigest()[:20]
        paths = self.job_paths(job_id)
        inner = "cd -- {} && {}; rc=$?; printf '%s\\n' \"$rc\" > {}; exit \"$rc\"".format(
            shlex.quote(cwd),
            " ".join(shlex.quote(x) for x in argv),
            shlex.quote(paths["exit"]),
        )
        cmd = (
            "mkdir -p -- {base} && "
            "if [ -f {pid} ]; then cat {pid}; "
            "else "
            "nohup setsid sh -c {inner} > {log} 2>&1 < /dev/null & pid=$!; "
            "start=$(awk '{{print $22}}' /proc/$pid/stat 2>/dev/null || true); "
            "boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true); "
            "if [ -z \"$start\" ] || [ -z \"$boot\" ]; then "
            "kill -TERM -- -\"$pid\" 2>/dev/null || true; exit 45; fi; "
            "printf '%s\\n' \"$pid\" > {pid}; "
            "printf '%s\\n' \"$start\" > {start_ticks}; "
            "printf '%s\\n' \"$boot\" > {boot_id}; "
            "printf '%s\\n' \"$pid\"; "
            "fi"
        ).format(
            base=shlex.quote(paths["base"]),
            pid=shlex.quote(paths["pid"]),
            start_ticks=shlex.quote(paths["start_ticks"]),
            boot_id=shlex.quote(paths["boot_id"]),
            inner=shlex.quote(inner),
            log=shlex.quote(paths["log"]),
        )
        r = self.backend.internal_exec(cmd)
        pid = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
        if r.exit_code != 0 or not pid.isdigit():
            raise BackendFailure("failed to start remote job")

        observed = self.rpc_job_status(rid, {"job_id": job_id, "max_log_bytes": 0})
        if observed["status"] != "VERIFIED":
            return self.response(
                rid,
                "OUTCOME_UNKNOWN",
                {"job_id": job_id, "pid": int(pid), "observed": observed.get("result")},
                "JOB_START_UNCERTAIN",
                "job metadata exists but current process identity/state could not be verified",
            )
        state = (observed.get("result") or {}).get("state")
        return self.response(
            rid,
            "VERIFIED",
            {"job_id": job_id, "pid": int(pid), "state": state, "argv": argv, "cwd": cwd},
        )

    def rpc_job_status(self, rid: str, p: dict[str, Any]) -> dict[str, Any]:
        job_id = p.get("job_id")
        paths = self.job_paths(job_id)
        raw_max_log = p.get("max_log_bytes", 32768)
        if isinstance(raw_max_log, bool) or not isinstance(raw_max_log, int):
            raise PolicyError("max_log_bytes must be an integer")
        if not 0 <= raw_max_log <= 131072:
            raise PolicyError("max_log_bytes must be between 0 and 131072")
        max_log = raw_max_log

        cmd = (
            "if [ -f {cancelled} ]; then printf 'CANCELLED\\n'; "
            "elif [ -f {exitf} ]; then printf 'EXIT '; cat {exitf}; "
            "elif [ -f {pid} ] && [ -f {start_ticks} ] && [ -f {boot_id} ]; then "
            "pid=$(cat {pid}); expected_start=$(cat {start_ticks}); expected_boot=$(cat {boot_id}); "
            "current_boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true); "
            "if [ \"$current_boot\" != \"$expected_boot\" ]; then printf 'IDENTITY_MISMATCH\\n'; "
            "elif [ ! -r /proc/$pid/stat ]; then printf 'UNKNOWN\\n'; "
            "else current_start=$(awk '{{print $22}}' /proc/$pid/stat 2>/dev/null || true); "
            "if [ \"$current_start\" = \"$expected_start\" ] && kill -0 \"$pid\" 2>/dev/null; "
            "then printf 'RUNNING\\n'; else printf 'IDENTITY_MISMATCH\\n'; fi; fi; "
            "elif [ -f {pid} ]; then printf 'IDENTITY_MISSING\\n'; "
            "else printf 'MISSING\\n'; fi; "
            "printf '%s\\n' '---LOG---'; "
            "if [ -f {log} ]; then tail -c {n} {log}; fi"
        ).format(
            exitf=shlex.quote(paths["exit"]),
            cancelled=shlex.quote(paths["cancelled"]),
            pid=shlex.quote(paths["pid"]),
            start_ticks=shlex.quote(paths["start_ticks"]),
            boot_id=shlex.quote(paths["boot_id"]),
            log=shlex.quote(paths["log"]),
            n=max_log,
        )
        r = self.backend.internal_exec(cmd)
        if r.exit_code != 0:
            raise BackendFailure("job status query failed")
        head, _, log = r.stdout.partition("---LOG---\n")
        state = head.strip()
        if state.startswith("EXIT "):
            try:
                code = int(state.split()[1])
            except (IndexError, ValueError) as exc:
                raise BackendFailure("invalid job exit metadata") from exc
            return self.response(
                rid,
                "VERIFIED",
                {"job_id": job_id, "state": "SUCCEEDED" if code == 0 else "FAILED", "exit_code": code, "log_tail": log},
            )
        if state == "CANCELLED":
            return self.response(rid, "VERIFIED", {"job_id": job_id, "state": "CANCELLED", "log_tail": log})
        if state == "RUNNING":
            return self.response(rid, "VERIFIED", {"job_id": job_id, "state": "RUNNING", "log_tail": log})
        if state == "MISSING":
            return self.response(rid, "FAILED", {"job_id": job_id}, "JOB_NOT_FOUND", "job metadata not found")
        if state in {"IDENTITY_MISMATCH", "IDENTITY_MISSING"}:
            return self.response(
                rid,
                "OUTCOME_UNKNOWN",
                {"job_id": job_id, "state": "UNKNOWN", "log_tail": log},
                "JOB_IDENTITY_UNKNOWN",
                "stored PID cannot be safely bound to the original job process",
            )
        return self.response(
            rid,
            "OUTCOME_UNKNOWN",
            {"job_id": job_id, "state": "UNKNOWN", "log_tail": log},
            "JOB_STATE_UNKNOWN",
            "pid disappeared without exit record",
        )

    def rpc_cancel_job(self, rid: str, p: dict[str, Any]) -> dict[str, Any]:
        job_id = p.get("job_id")
        observed = self.rpc_job_status(rid, {"job_id": job_id, "max_log_bytes": 0})
        if observed["status"] == "FAILED":
            return observed
        if observed["status"] == "OUTCOME_UNKNOWN":
            return self.response(
                rid,
                "OUTCOME_UNKNOWN",
                {"job_id": job_id, "observed": observed.get("result")},
                "CANCEL_PRECONDITION_UNKNOWN",
                "job identity/state is uncertain; refusing to signal any process",
            )
        observed_state = (observed.get("result") or {}).get("state")
        if observed_state == "CANCELLED":
            return self.response(rid, "VERIFIED", {"job_id": job_id, "state": "CANCELLED"})
        if observed_state in {"SUCCEEDED", "FAILED"}:
            return self.response(
                rid,
                "FAILED",
                {"job_id": job_id, "state": observed_state, "exit_code": (observed.get("result") or {}).get("exit_code")},
                "JOB_ALREADY_TERMINAL",
                "job already reached a terminal state before cancellation",
            )

        paths = self.job_paths(job_id)
        cmd = (
            "if [ ! -f {pid} ] || [ ! -f {start_ticks} ] || [ ! -f {boot_id} ]; then exit 44; fi; "
            "pid=$(cat {pid}); expected_start=$(cat {start_ticks}); expected_boot=$(cat {boot_id}); "
            "current_boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true); "
            "if [ \"$current_boot\" != \"$expected_boot\" ] || [ ! -r /proc/$pid/stat ]; then exit 45; fi; "
            "current_start=$(awk '{{print $22}}' /proc/$pid/stat 2>/dev/null || true); "
            "if [ \"$current_start\" != \"$expected_start\" ]; then exit 45; fi; "
            "if ! kill -0 -- -\"$pid\" 2>/dev/null; then exit 47; fi; "
            "kill -TERM -- -\"$pid\" 2>/dev/null || true; "
            "i=0; while [ $i -lt 20 ] && kill -0 -- -\"$pid\" 2>/dev/null; do sleep 0.1; i=$((i+1)); done; "
            "if kill -0 -- -\"$pid\" 2>/dev/null; then kill -KILL -- -\"$pid\" 2>/dev/null || true; fi; "
            "i=0; while [ $i -lt 20 ] && kill -0 -- -\"$pid\" 2>/dev/null; do sleep 0.1; i=$((i+1)); done; "
            "if kill -0 -- -\"$pid\" 2>/dev/null; then exit 46; fi; "
            "printf 'cancelled\\n' > {cancelled}; printf 'CANCELLED\\n'"
        ).format(
            pid=shlex.quote(paths["pid"]),
            start_ticks=shlex.quote(paths["start_ticks"]),
            boot_id=shlex.quote(paths["boot_id"]),
            cancelled=shlex.quote(paths["cancelled"]),
        )
        r = self.backend.internal_exec(cmd, max(5.0, self.cfg.backend_timeout_s))
        if r.exit_code == 44:
            return self.response(rid, "FAILED", None, "JOB_NOT_FOUND", "job identity metadata not found")
        if r.exit_code == 45:
            return self.response(
                rid,
                "OUTCOME_UNKNOWN",
                {"job_id": job_id},
                "JOB_IDENTITY_UNKNOWN",
                "stored PID cannot be safely bound to the original job; refusing to signal it",
            )
        if r.exit_code == 47:
            return self.response(
                rid,
                "OUTCOME_UNKNOWN",
                {"job_id": job_id},
                "JOB_STATE_UNKNOWN",
                "job process is already absent without a terminal record",
            )
        if r.exit_code == 46:
            return self.response(
                rid,
                "OUTCOME_UNKNOWN",
                {"job_id": job_id},
                "CANCEL_NOT_TERMINATED",
                "process group still exists after TERM/KILL",
            )
        if r.exit_code != 0 or r.stdout.strip() != "CANCELLED":
            return self.response(rid, "OUTCOME_UNKNOWN", {"job_id": job_id}, "CANCEL_UNCERTAIN", r.stderr[-500:])
        return self.response(rid, "VERIFIED", {"job_id": job_id, "state": "CANCELLED"})

    def rpc_transfer(self, rid: str, p: dict[str, Any]) -> dict[str, Any]:
        direction = p.get("direction")
        if direction == "upload":
            data = self.decode_content(p)
            content_sha = normalize_sha256_hex(p.get("content_sha256"), "content_sha256", allow_none=True)
            if content_sha is not None and sha256(data) != content_sha:
                raise PolicyError("content_sha256 does not match upload payload")
            expected = normalize_sha256_hex(p.get("expected_sha256"), "expected_sha256", allow_none=True)
            path = self.policy.user_path(p.get("path"))
            result = self.backend.write_bytes_cas(path, data, expected)
            if not result["ok"]:
                return self.response(rid, "FAILED", result, result["code"], "transfer CAS failed")
            return self.response(rid, "VERIFIED", {"direction": direction, "path": path, **result})
        if direction == "download":
            path = self.policy.user_path(p.get("path"))
            data = self.backend.read_bytes(path)
            return self.response(rid, "VERIFIED", {"direction": direction, "path": path, "encoding": "base64", "content": base64.b64encode(data).decode(), "sha256": sha256(data), "bytes": len(data)})
        raise PolicyError("transfer direction must be upload or download")

    def rpc_reconcile(self, rid: str, p: dict[str, Any]) -> dict[str, Any]:
        kind = p.get("kind")
        if kind == "request":
            target = self.policy.check_request_id(p.get("target_request_id"))
            try:
                old = self.ledger.get(target)
            except Exception as exc:
                return self.response(
                    rid,
                    "FAILED",
                    {"target_request_id": target},
                    "LEDGER_UNAVAILABLE",
                    f"idempotency ledger unavailable during reconciliation: {type(exc).__name__}",
                )
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
            path = self.policy.user_path(p.get("path"))
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
