import math
import unittest
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


if __name__ == "__main__":
    unittest.main()
