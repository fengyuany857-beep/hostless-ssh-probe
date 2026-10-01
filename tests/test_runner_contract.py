import math
import stat
import unittest
import vcw_runner as vr
from types import SimpleNamespace

from vcw_runner import (
    BackendUncertain,
    ExecResult,
    Policy,
    PolicyError,
    RunnerService,
    SSHBackend,
    canonical_request_fingerprint,
)


class ContractTests(unittest.TestCase):
    def test_timeout_rejects_non_finite_and_non_positive_values(self):
        policy = Policy("/srv/project", frozenset({"exec"}), frozenset({"python3"}))
        for value in (0, -1, float("nan"), float("inf"), True):
            with self.assertRaises(PolicyError):
                policy.timeout(value)
        self.assertEqual(policy.timeout(0.25), 0.25)
        self.assertEqual(policy.timeout(999), 300.0)

    def test_request_fingerprint_binds_action_not_session_correlation(self):
        a = canonical_request_fingerprint("srv", "write_file", {"path": "a", "content": "x"})
        same = canonical_request_fingerprint("srv", "write_file", {"content": "x", "path": "a"})
        changed = canonical_request_fingerprint("srv", "write_file", {"path": "a", "content": "y"})
        other_method = canonical_request_fingerprint("srv", "transfer", {"path": "a", "content": "x"})
        self.assertEqual(a, same)
        self.assertNotEqual(a, changed)
        self.assertNotEqual(a, other_method)

    def test_ledger_finish_failure_becomes_outcome_unknown(self):
        service = RunnerService.__new__(RunnerService)
        service.cfg = SimpleNamespace(server_id="srv")
        service.policy = Policy("/srv/project", frozenset({"write_file"}), frozenset())
        service.backend = SimpleNamespace(generation=3)

        class Ledger:
            def begin(self, request_id, method, fingerprint, reconcile_hint=None):
                return None
            def finish(self, request_id, status, response):
                raise RuntimeError("db unavailable")

        service.ledger = Ledger()
        service.rpc_write_file = lambda rid, p: service.response(rid, "VERIFIED", {"sha256": "a" * 64})

        result = service.dispatch({
            "server_id": "srv",
            "session_id": "ses-1",
            "request_id": "req-1",
            "method": "write_file",
            "params": {"path": "a.txt", "content": "x"},
        })
        self.assertEqual(result["status"], "OUTCOME_UNKNOWN")
        self.assertEqual(result["error"]["code"], "LEDGER_COMMIT_FAILED")
        self.assertEqual(result["result"]["observed_action_status"], "VERIFIED")
        self.assertEqual(result["session_id"], "ses-1")

    def test_job_status_preserves_cancelled_terminal_state(self):
        service = RunnerService.__new__(RunnerService)
        service.cfg = SimpleNamespace(project_root="/srv/project", server_id="srv")
        service.policy = Policy("/srv/project", frozenset(), frozenset())

        class Backend:
            def internal_exec(self, command, timeout_s=None):
                return ExecResult(0, "CANCELLED\n---LOG---\n", "")

        service.backend = Backend()
        service.response = RunnerService.response.__get__(service, RunnerService)
        service.backend.generation = 1
        result = service.rpc_job_status("req", {"job_id": "job_abcdefgh"})
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["result"]["state"], "CANCELLED")

    def test_cancel_refuses_unknown_process_identity(self):
        service = RunnerService.__new__(RunnerService)
        service.cfg = SimpleNamespace(project_root="/srv/project", backend_timeout_s=5, server_id="srv")
        service.policy = Policy("/srv/project", frozenset(), frozenset())

        class Backend:
            generation = 1
            def __init__(self):
                self.calls = 0
            def internal_exec(self, command, timeout_s=None):
                self.calls += 1
                if self.calls == 1:
                    return ExecResult(0, "RUNNING\n---LOG---\n", "")
                return ExecResult(45, "", "")

        service.backend = Backend()
        service.response = RunnerService.response.__get__(service, RunnerService)
        result = service.rpc_cancel_job("req", {"job_id": "job_abcdefgh"})
        self.assertEqual(result["status"], "OUTCOME_UNKNOWN")
        self.assertEqual(result["error"]["code"], "JOB_IDENTITY_UNKNOWN")

    def test_sftp_rename_failure_is_uncertain(self):
        policy = Policy("/srv/project", frozenset({"write_file"}), frozenset())
        cfg = SimpleNamespace(max_file_bytes=1024)

        class RemoteFile:
            def __init__(self):
                self.data = bytearray()
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def write(self, data):
                self.data.extend(data)
            def flush(self):
                pass

        class Sftp:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def normalize(self, path):
                return path
            def lstat(self, path):
                raise FileNotFoundError(path)
            def open(self, path, mode):
                return RemoteFile()
            def chmod(self, path, mode):
                pass
            def posix_rename(self, src, dst):
                raise OSError("connection lost during rename")
            def remove(self, path):
                pass

        class Client:
            def open_sftp(self):
                return Sftp()

        backend = SSHBackend(cfg, policy)
        backend.connect = lambda: Client()
        backend.reset = lambda: None

        with self.assertRaisesRegex(BackendUncertain, "rename outcome is unknown"):
            backend.write_bytes_cas("/srv/project/a.txt", b"x", None)

    def test_patch_requires_independent_postcondition(self):
        service = RunnerService.__new__(RunnerService)
        service.cfg = SimpleNamespace(project_root="/srv/project", backend_timeout_s=5, server_id="srv")
        service.policy = Policy("/srv/project", frozenset({"apply_patch"}), frozenset({"git"}))

        class Backend:
            generation = 1
            def __init__(self):
                self.exec_calls = 0
            def canonical_user_target(self, path):
                return "/srv/project/" + path
            def internal_exec(self, command, timeout_s=None):
                return ExecResult(0, "", "")
            def write_bytes_cas(self, path, data, expected, **kwargs):
                return {"ok": True, "sha256": "a" * 64, "previous_sha256": None, "bytes": len(data)}
            def exec_argv(self, argv, cwd, timeout_s=None):
                self.exec_calls += 1
                if self.exec_calls <= 2:
                    return ExecResult(0, "", "")
                return ExecResult(1, "", "reverse check failed")

        service.backend = Backend()
        service.response = RunnerService.response.__get__(service, RunnerService)
        patch = "--- /dev/null\n+++ b/a.txt\n@@ -0,0 +1 @@\n+x\n"
        result = service.rpc_apply_patch("req", {"patch": patch})
        self.assertEqual(result["status"], "OUTCOME_UNKNOWN")
        self.assertEqual(result["error"]["code"], "PATCH_POSTCONDITION_UNVERIFIED")

    def test_unknown_envelope_fields_are_denied_before_execution(self):
        service = RunnerService.__new__(RunnerService)
        service.cfg = SimpleNamespace(server_id="srv")
        service.policy = Policy("/srv/project", frozenset({"write_file"}), frozenset())
        service.backend = SimpleNamespace(generation=1)

        class Ledger:
            def begin(self, *args):
                raise AssertionError("ledger must not be touched")
        service.ledger = Ledger()

        with self.assertRaisesRegex(PolicyError, "unsupported RPC envelope fields"):
            service.dispatch({
                "server_id": "srv",
                "request_id": "req-1",
                "method": "write_file",
                "params": {"path": "a.txt", "content": "x"},
                "host": "127.0.0.1",
            })

    def test_backend_still_exposes_exec_argv(self):
        self.assertTrue(callable(getattr(SSHBackend, "exec_argv", None)))

    def test_ledger_unavailable_blocks_side_effect(self):
        service = RunnerService.__new__(RunnerService)
        service.cfg = SimpleNamespace(server_id="srv")
        service.policy = Policy("/srv/project", frozenset({"write_file"}), frozenset())
        service.backend = SimpleNamespace(generation=2)

        class Ledger:
            def begin(self, request_id, method, fingerprint):
                raise RuntimeError("db offline")

        service.ledger = Ledger()
        called = {"value": False}

        def fake_write(rid, params):
            called["value"] = True
            return service.response(rid, "VERIFIED", {"sha256": "a" * 64})

        service.rpc_write_file = fake_write
        result = service.dispatch({
            "server_id": "srv",
            "request_id": "req-ledger-down",
            "method": "write_file",
            "params": {"path": "a.txt", "content": "x"},
        })
        self.assertFalse(called["value"])
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["error"]["code"], "LEDGER_UNAVAILABLE")

    def test_transfer_download_skips_side_effect_ledger(self):
        service = RunnerService.__new__(RunnerService)
        service.cfg = SimpleNamespace(server_id="srv")
        service.policy = Policy("/srv/project", frozenset({"transfer"}), frozenset())

        class Backend:
            generation = 1
            def read_bytes(self, path):
                return b"abc"

        class Ledger:
            def begin(self, *args):
                self.called = True

        ledger = Ledger()
        ledger.called = False
        service.backend = Backend()
        service.ledger = ledger
        result = service.dispatch({
            "server_id": "srv",
            "request_id": "req-download",
            "method": "transfer",
            "params": {"direction": "download", "path": "a.bin"},
        })
        self.assertFalse(ledger.called)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["result"]["bytes"], 3)

    def test_cached_response_uses_current_session_correlation(self):
        service = RunnerService.__new__(RunnerService)
        service.cfg = SimpleNamespace(server_id="srv")
        service.policy = Policy("/srv/project", frozenset({"write_file"}), frozenset())
        service.backend = SimpleNamespace(generation=4)

        cached = {
            "rpc_version": "vcw.runner.v1",
            "request_id": "req-replay",
            "server_id": "srv",
            "connection_generation": 2,
            "status": "VERIFIED",
            "result": {"sha256": "a" * 64},
            "error": None,
            "session_id": "ses-old",
        }

        class Ledger:
            def begin(self, request_id, method, fingerprint):
                return {
                    "method": method,
                    "state": "VERIFIED",
                    "response": cached,
                    "updated_at": 1.0,
                    "request_fingerprint": fingerprint,
                }

        service.ledger = Ledger()
        result = service.dispatch({
            "server_id": "srv",
            "session_id": "ses-new",
            "request_id": "req-replay",
            "method": "write_file",
            "params": {"path": "a.txt", "content": "x"},
        })
        self.assertEqual(result["session_id"], "ses-new")
        self.assertEqual(cached["session_id"], "ses-old")

    def test_connection_generation_tracks_successful_connection_epochs(self):
        cfg = SimpleNamespace(
            ssh_host_key_sha256="A" * 43,
            target_host="example.invalid",
            target_port=22,
            target_user="runner",
            ssh_private_key="key",
            backend_timeout_s=1,
        )
        policy = Policy("/srv/project", frozenset(), frozenset())
        backend = SSHBackend(cfg, policy)

        class Transport:
            def __init__(self):
                self.active = False
            def is_active(self):
                return self.active

        class Client:
            def __init__(self):
                self.transport = Transport()
            def set_missing_host_key_policy(self, policy):
                self.policy = policy
            def connect(self, *args, **kwargs):
                self.transport.active = True
            def get_transport(self):
                return self.transport
            def close(self):
                self.transport.active = False

        old_client = vr.paramiko.SSHClient
        old_loader = vr.load_private_key
        try:
            vr.paramiko.SSHClient = Client
            vr.load_private_key = lambda text: object()
            backend.connect()
            self.assertEqual(backend.generation, 1)
            backend.connect()
            self.assertEqual(backend.generation, 1)
            backend.reset()
            self.assertEqual(backend.generation, 1)
            backend.connect()
            self.assertEqual(backend.generation, 2)
        finally:
            vr.paramiko.SSHClient = old_client
            vr.load_private_key = old_loader

    def test_atomic_write_preserves_existing_mode(self):
        policy = Policy("/srv/project", frozenset({"write_file"}), frozenset())
        cfg = SimpleNamespace(max_file_bytes=1024)

        class Attr:
            def __init__(self, mode, size):
                self.st_mode = mode
                self.st_size = size

        class RemoteFile:
            def __init__(self, fs, path, mode):
                self.fs = fs
                self.path = path
                self.mode = mode
                self.buf = bytearray(fs.get(path, {}).get("data", b""))
                if mode == "wb":
                    self.buf = bytearray()
            def __enter__(self):
                return self
            def __exit__(self, *args):
                if self.mode == "wb":
                    self.fs.setdefault(self.path, {})["data"] = bytes(self.buf)
                return False
            def write(self, data):
                self.buf.extend(data)
            def read(self, n=-1):
                data = bytes(self.buf)
                return data if n < 0 else data[:n]
            def flush(self):
                pass

        class Sftp:
            def __init__(self):
                self.fs = {
                    "/srv/project/tool.sh": {"data": b"old\n", "mode": 0o755}
                }
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def normalize(self, path):
                return path
            def lstat(self, path):
                if path not in self.fs:
                    raise FileNotFoundError(path)
                entry = self.fs[path]
                return Attr(stat.S_IFREG | entry["mode"], len(entry["data"]))
            def open(self, path, mode):
                return RemoteFile(self.fs, path, mode)
            def chmod(self, path, mode):
                self.fs.setdefault(path, {"data": b""})["mode"] = mode
            def posix_rename(self, src, dst):
                self.fs[dst] = self.fs.pop(src)
            def remove(self, path):
                self.fs.pop(path, None)

        class Client:
            def __init__(self, sftp):
                self.sftp = sftp
            def open_sftp(self):
                return self.sftp

        sftp = Sftp()
        backend = SSHBackend(cfg, policy)
        backend.connect = lambda: Client(sftp)
        result = backend.write_bytes_cas("/srv/project/tool.sh", b"new\n", None)
        self.assertTrue(result["ok"])
        self.assertEqual(result["mode"], "0755")
        self.assertEqual(sftp.fs["/srv/project/tool.sh"]["mode"], 0o755)
        self.assertEqual(sftp.fs["/srv/project/tool.sh"]["data"], b"new\n")

    def test_cancel_does_not_signal_already_terminal_job(self):
        service = RunnerService.__new__(RunnerService)
        service.cfg = SimpleNamespace(project_root="/srv/project", backend_timeout_s=5, server_id="srv")
        service.policy = Policy("/srv/project", frozenset(), frozenset())

        class Backend:
            generation = 1
            def __init__(self):
                self.calls = 0
            def internal_exec(self, command, timeout_s=None):
                self.calls += 1
                return ExecResult(0, "EXIT 0\n---LOG---\n", "")

        backend = Backend()
        service.backend = backend
        service.response = RunnerService.response.__get__(service, RunnerService)
        result = service.rpc_cancel_job("req", {"job_id": "job_abcdefgh"})
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["error"]["code"], "JOB_ALREADY_TERMINAL")
        self.assertEqual(backend.calls, 1)

    def test_incomplete_existing_claim_never_reexecutes(self):
        service = RunnerService.__new__(RunnerService)
        service.cfg = SimpleNamespace(server_id="srv")
        service.policy = Policy("/srv/project", frozenset({"write_file"}), frozenset())
        service.backend = SimpleNamespace(generation=1)

        class Ledger:
            def begin(self, request_id, method, fingerprint, reconcile_hint=None):
                return {
                    "method": method,
                    "state": "FAILED",
                    "response": None,
                    "updated_at": 1.0,
                    "request_fingerprint": fingerprint,
                    "reconcile_hint": reconcile_hint,
                }

        service.ledger = Ledger()
        called = {"value": False}
        def fake_write(rid, params):
            called["value"] = True
            return service.response(rid, "VERIFIED", {})
        service.rpc_write_file = fake_write

        result = service.dispatch({
            "server_id": "srv",
            "request_id": "req-incomplete",
            "method": "write_file",
            "params": {"path": "a.txt", "content": "x"},
        })
        self.assertFalse(called["value"])
        self.assertEqual(result["status"], "OUTCOME_UNKNOWN")
        self.assertEqual(result["error"]["code"], "REQUEST_INCOMPLETE")

    def test_uncertain_write_returns_file_reconcile_hint(self):
        service = RunnerService.__new__(RunnerService)
        service.cfg = SimpleNamespace(server_id="srv")
        service.policy = Policy("/srv/project", frozenset({"write_file"}), frozenset())
        service.backend = SimpleNamespace(generation=2)

        class Ledger:
            def begin(self, request_id, method, fingerprint, reconcile_hint=None):
                self.hint = reconcile_hint
                return None
            def finish(self, request_id, status, response):
                self.response = response

        ledger = Ledger()
        service.ledger = ledger
        def uncertain_write(rid, params):
            raise BackendUncertain("connection lost after rename")
        service.rpc_write_file = uncertain_write

        result = service.dispatch({
            "server_id": "srv",
            "request_id": "req-uncertain-write",
            "method": "write_file",
            "params": {"path": "a.txt", "content": "hello"},
        })
        hint = result["result"]["reconcile_hint"]
        self.assertEqual(result["status"], "OUTCOME_UNKNOWN")
        self.assertEqual(hint["kind"], "file")
        self.assertEqual(hint["path"], "/srv/project/a.txt")
        self.assertEqual(hint["sha256"], __import__("hashlib").sha256(b"hello").hexdigest())
        self.assertEqual(ledger.hint, hint)

    def test_exec_transport_loss_is_uncertain_and_resets_connection(self):
        policy = Policy("/srv/project", frozenset({"exec"}), frozenset({"python3"}))
        cfg = SimpleNamespace(
            backend_timeout_s=1,
            max_output_bytes=1024,
            exec_path="/usr/bin:/bin",
        )
        backend = SSHBackend(cfg, policy)
        backend.connect = lambda: object()
        reset = {"count": 0}
        backend.reset = lambda: reset.__setitem__("count", reset["count"] + 1)

        old_runner = vr.run_command_channel
        try:
            def fail_transport(*args, **kwargs):
                raise vr.paramiko.SSHException("connection lost")
            vr.run_command_channel = fail_transport
            with self.assertRaisesRegex(BackendUncertain, "remote command outcome is unknown"):
                backend.internal_exec("true", 1)
        finally:
            vr.run_command_channel = old_runner

        self.assertEqual(reset["count"], 1)

    def test_canonical_path_cannot_alias_git_control_metadata(self):
        policy = Policy("/srv/project", frozenset(), frozenset())
        cfg = SimpleNamespace()

        class Sftp:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def normalize(self, path):
                if path == "/srv/project/alias":
                    return "/srv/project/.git"
                if path == "/srv/project/alias/config":
                    return "/srv/project/.git/config"
                return path

        class Client:
            def open_sftp(self):
                return Sftp()

        backend = SSHBackend(cfg, policy)
        backend.connect = lambda: Client()
        with self.assertRaisesRegex(PolicyError, "control metadata"):
            backend.canonical_existing_path("/srv/project/alias/config")

    def test_new_write_parent_symlink_cannot_alias_runner_metadata(self):
        policy = Policy("/srv/project", frozenset({"write_file"}), frozenset())
        cfg = SimpleNamespace(max_file_bytes=1024)

        class Sftp:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def normalize(self, path):
                if path == "/srv/project/alias":
                    return "/srv/project/.vcw-runner"
                return path

        class Client:
            def open_sftp(self):
                return Sftp()

        backend = SSHBackend(cfg, policy)
        backend.connect = lambda: Client()
        with self.assertRaisesRegex(PolicyError, "control metadata"):
            backend.write_bytes_cas("/srv/project/alias/evil", b"x", None)

    def test_internal_patch_stage_can_use_runner_control_metadata(self):
        policy = Policy("/srv/project", frozenset(), frozenset())
        self.assertEqual(policy.path("/srv/project/.vcw-runner/tmp/x.patch"), "/srv/project/.vcw-runner/tmp/x.patch")
        with self.assertRaises(PolicyError):
            policy.user_path("/srv/project/.vcw-runner/tmp/x.patch")

    def test_internal_exec_uses_project_local_runtime_home_and_umask(self):
        policy = Policy("/srv/project", frozenset({"exec"}), frozenset({"python3"}))
        cfg = SimpleNamespace(
            backend_timeout_s=2,
            max_output_bytes=1024,
            exec_path="/usr/bin:/bin",
        )
        backend = SSHBackend(cfg, policy)
        backend.connect = lambda: object()
        seen = {}

        old_runner = vr.run_command_channel
        try:
            def capture(client, command, **kwargs):
                seen["command"] = command
                return 0, "", ""
            vr.run_command_channel = capture
            result = backend.internal_exec("python3 -V", 1)
        finally:
            vr.run_command_channel = old_runner

        self.assertEqual(result.exit_code, 0)
        command = seen["command"]
        self.assertIn("umask 077", command)
        self.assertIn("/srv/project/.vcw-runner/runtime-home", command)
        self.assertIn("XDG_CACHE_HOME=", command)
        self.assertIn("NPM_CONFIG_CACHE=", command)
        self.assertIn("PATH=/usr/bin:/bin", command)


if __name__ == "__main__":
    unittest.main()
