import math
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
            def begin(self, request_id, method, fingerprint):
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
            def internal_exec(self, command, timeout_s=None):
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
            def internal_exec(self, command, timeout_s=None):
                return ExecResult(0, "", "")
            def write_bytes_cas(self, path, data, expected):
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


if __name__ == "__main__":
    unittest.main()
