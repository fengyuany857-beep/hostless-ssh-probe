import sys
import tempfile
import threading
import types
import unittest
from concurrent.futures import ThreadPoolExecutor

fake = types.ModuleType("paramiko")
class MissingHostKeyPolicy: pass
class _Key:
    @classmethod
    def from_private_key(cls, *args, **kwargs):
        raise ValueError
fake.MissingHostKeyPolicy = MissingHostKeyPolicy
fake.Ed25519Key = _Key
fake.RSAKey = _Key
fake.ECDSAKey = _Key
fake.PKey = object
fake.SSHClient = object
fake.SSHException = RuntimeError
sys.modules.setdefault("paramiko", fake)

from vcw_runner import IdempotencyLedger, PolicyError


class IdempotencyLedgerTests(unittest.TestCase):
    def test_concurrent_begin_is_atomic(self):
        with tempfile.TemporaryDirectory() as td:
            store = IdempotencyLedger(td + "/state.sqlite3")
            barrier = threading.Barrier(8)

            def run():
                barrier.wait()
                return store.begin("same-request", "write_file")

            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda _: run(), range(8)))

            self.assertEqual(sum(x is None for x in results), 1)
            self.assertEqual(sum(x is not None and x["state"] == "RUNNING" for x in results), 7)

    def test_request_id_cannot_change_method(self):
        with tempfile.TemporaryDirectory() as td:
            store = IdempotencyLedger(td + "/state.sqlite3")
            self.assertIsNone(store.begin("same-request", "write_file"))
            with self.assertRaises(PolicyError):
                store.begin("same-request", "exec")


if __name__ == "__main__":
    unittest.main()
