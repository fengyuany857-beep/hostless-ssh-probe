import os
import unittest
from unittest import mock

from vcw_runner import Config


class ConfigTests(unittest.TestCase):
    def base_env(self):
        return {
            "RUNNER_TOKEN": "token",
            "VCW_SERVER_ID": "srv-1",
            "TARGET_HOST": "127.0.0.1",
            "TARGET_PORT": "22",
            "TARGET_USER": "runner",
            "VCW_PROJECT_ROOT": "/srv/project",
            "SSH_PRIVATE_KEY": "dummy-private-key",
            "SSH_HOST_KEY_SHA256": "A" * 43,
            "VCW_ALLOWED_TOOLS": "read_file,write_file,exec,reconcile",
            "VCW_ALLOWED_EXEC": "git,python3",
            "VCW_EXEC_PATH": "/usr/local/bin:/usr/bin:/bin",
            "VCW_BACKEND_TIMEOUT_S": "20",
            "VCW_MAX_FILE_BYTES": "4096",
            "VCW_MAX_OUTPUT_BYTES": "4096",
            "VCW_MAX_INFLIGHT": "4",
            "VCW_LEDGER_DB": "/tmp/test-ledger.sqlite3",
            "PORT": "8080",
        }

    def load(self, **updates):
        env = self.base_env()
        env.update({k: str(v) for k, v in updates.items()})
        with mock.patch.dict(os.environ, env, clear=True):
            return Config.from_env()

    def test_valid_config(self):
        cfg = self.load()
        self.assertEqual(cfg.target_user, "runner")
        self.assertEqual(cfg.project_root, "/srv/project")
        self.assertEqual(cfg.max_inflight, 4)

    def test_root_target_user_is_forbidden(self):
        with self.assertRaisesRegex(RuntimeError, "TARGET_USER=root"):
            self.load(TARGET_USER="root")

    def test_project_root_cannot_be_filesystem_root(self):
        with self.assertRaisesRegex(RuntimeError, "non-root path"):
            self.load(VCW_PROJECT_ROOT="/")

    def test_project_root_must_be_normalized(self):
        with self.assertRaisesRegex(RuntimeError, "normalized"):
            self.load(VCW_PROJECT_ROOT="/srv/project/../other")

    def test_unknown_tool_configuration_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "unsupported v1 methods"):
            self.load(VCW_ALLOWED_TOOLS="read_file,totally_new_tool")

    def test_exec_allowlist_requires_bare_names(self):
        with self.assertRaisesRegex(RuntimeError, "bare executable names"):
            self.load(VCW_ALLOWED_EXEC="/tmp/git")

    def test_exec_path_requires_normalized_absolute_directories(self):
        with self.assertRaisesRegex(RuntimeError, "VCW_EXEC_PATH"):
            self.load(VCW_EXEC_PATH="/usr/bin:relative")

    def test_max_inflight_must_be_positive_and_bounded(self):
        for value in ("0", "-1", "129"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(RuntimeError, "VCW_MAX_INFLIGHT"):
                    self.load(VCW_MAX_INFLIGHT=value)


if __name__ == "__main__":
    unittest.main()
