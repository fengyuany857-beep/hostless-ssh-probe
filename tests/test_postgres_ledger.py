import os
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor

from vcw_runner import IdempotencyLedger, PolicyError


class PostgresLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.url = os.environ.get("TEST_POSTGRES_URL", "")
        if not cls.url:
            raise unittest.SkipTest("TEST_POSTGRES_URL is not configured")

    def rid(self, suffix):
        return "test-" + uuid.uuid4().hex + "-" + suffix

    def test_terminal_response_survives_new_ledger_instance(self):
        rid = self.rid("replay")
        first = IdempotencyLedger(self.url)
        self.assertIsNone(first.begin(rid, "write_file"))

        response = {
            "rpc_version": "vcw.runner.v1",
            "request_id": rid,
            "status": "VERIFIED",
            "result": {"sha256": "a" * 64},
            "error": None,
        }
        first.finish(rid, "VERIFIED", response)

        second = IdempotencyLedger(self.url)
        prior = second.begin(rid, "write_file")
        self.assertIsNotNone(prior)
        self.assertEqual(prior["state"], "VERIFIED")
        self.assertEqual(prior["response"], response)

    def test_request_id_cannot_change_method_across_instances(self):
        rid = self.rid("method")
        first = IdempotencyLedger(self.url)
        second = IdempotencyLedger(self.url)
        self.assertIsNone(first.begin(rid, "write_file"))
        with self.assertRaises(PolicyError):
            second.begin(rid, "exec")

    def test_concurrent_begin_has_exactly_one_owner(self):
        rid = self.rid("concurrent")
        ledgers = [IdempotencyLedger(self.url) for _ in range(8)]
        barrier = threading.Barrier(8)

        def attempt(index):
            barrier.wait()
            return ledgers[index].begin(rid, "write_file")

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(8)))

        self.assertEqual(sum(x is None for x in results), 1)
        self.assertEqual(sum(x is not None and x["state"] == "RUNNING" for x in results), 7)


if __name__ == "__main__":
    unittest.main()
