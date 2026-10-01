import json
import re
import unittest
from pathlib import Path

from vcw_runner import KNOWN_METHODS, SAFE_ID, STATUSES


ROOT = Path(__file__).resolve().parents[1]


class SchemaContractTests(unittest.TestCase):
    def load(self, name):
        return json.loads((ROOT / "docs" / name).read_text())

    def test_request_method_enum_matches_runtime(self):
        schema = self.load("rpc-v1-request.schema.json")
        methods = set(schema["properties"]["method"]["enum"])
        self.assertEqual(methods, set(KNOWN_METHODS))

    def test_response_status_enum_matches_runtime(self):
        schema = self.load("rpc-v1-response.schema.json")
        statuses = set(schema["properties"]["status"]["enum"])
        self.assertEqual(statuses, set(STATUSES))

    def test_request_and_session_ids_use_runtime_safe_id_pattern(self):
        schema = self.load("rpc-v1-request.schema.json")
        self.assertEqual(schema["properties"]["request_id"]["pattern"], SAFE_ID.pattern)
        self.assertEqual(schema["properties"]["session_id"]["pattern"], SAFE_ID.pattern)


if __name__ == "__main__":
    unittest.main()
