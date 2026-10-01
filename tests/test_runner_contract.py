import math
import unittest
from types import SimpleNamespace

from vcw_runner import (
    ExecResult,
    Policy,
    PolicyError,
    RunnerService,
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

    def test_request_fingerprint_binds_session_and_params(self):
        a = canonical_request_fingerprint("srv", "ses-a", "write_file", {"path": "a", "content": "x"})
        b = canonical_request_fingerprint("srv", "ses-b", "write_file", {"path": "a", "content": "x"})
        c = canonical_request_fingerprint("srv", "ses-a", "write_file", {"path": "a", "content": "y"})
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, c)

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


if __name__ == "__main__":
    unittest.main()
