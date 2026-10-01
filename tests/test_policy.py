import sys
import types
import unittest

fake = types.ModuleType('paramiko')
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
sys.modules.setdefault('paramiko', fake)

from vcw_runner import Policy, PolicyError, SSHBackend, normalize_host_key_sha256

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.p = Policy('/srv/projects/demo', frozenset({'read_file','exec','apply_patch'}), frozenset({'git','python3'}))

    def test_inside_root(self):
        self.assertEqual(self.p.path('src/a.py'), '/srv/projects/demo/src/a.py')

    def test_escape_denied(self):
        for value in ('../secret','/etc/passwd','../../srv/projects/demo2'):
            with self.assertRaises(PolicyError):
                self.p.path(value)

    def test_exec_allowlist(self):
        self.assertEqual(self.p.argv(['git','status']), ['git','status'])
        with self.assertRaises(PolicyError):
            self.p.argv(['bash','-lc','cat /etc/passwd'])

    def test_patch_escape_denied(self):
        with self.assertRaises(PolicyError):
            self.p.patch_paths('--- a/x\n+++ b/../../etc/passwd\n@@ -0,0 +1 @@\n+x\n')

    def test_patch_path(self):
        self.assertEqual(self.p.patch_paths('--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-a\n+b\n'), ['a.txt'])

    def test_host_key_sha256_normalization(self):
        fp = 'mvDJ2jESSWKOfTD9wJH1217yaaHOZHhXS6ApxoihdlY'
        self.assertEqual(normalize_host_key_sha256(fp), fp)
        self.assertEqual(normalize_host_key_sha256('SHA256:' + fp), fp)
        self.assertEqual(normalize_host_key_sha256('sha256:' + fp), fp)

    def test_host_key_sha256_rejects_invalid(self):
        with self.assertRaises(RuntimeError):
            normalize_host_key_sha256('sha256:not-a-fingerprint')

    def test_write_rejects_symlink_leaf_before_following_it(self):
        policy = Policy('/srv/projects/demo', frozenset({'write_file'}), frozenset())
        cfg = SimpleNamespace(max_file_bytes=1024)

        class FakeSftp:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def normalize(self, path):
                return path
            def lstat(self, path):
                return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777)

        class FakeClient:
            def open_sftp(self):
                return FakeSftp()

        backend = SSHBackend(cfg, policy)
        backend.connect = lambda: FakeClient()

        with self.assertRaisesRegex(PolicyError, 'refusing to overwrite symlink'):
            backend.write_bytes_cas('/srv/projects/demo/link.txt', b'x', None)

if __name__ == '__main__':
    unittest.main()
