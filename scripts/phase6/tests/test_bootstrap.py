import hashlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))
import bootstrap
import snapshot


class BootstrapTests(unittest.TestCase):
    def test_checksum_failure_rejects_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(bootstrap.urllib.request, 'urlopen', return_value=io.BytesIO(b'tampered')):
                with self.assertRaises(ValueError):
                    bootstrap.download('https://example.invalid/archive', Path(tmp)/'archive', '0'*64)

    def test_verified_archive_cache_does_not_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'archive'
            path.write_bytes(b'verified')
            with patch.object(bootstrap.urllib.request, 'urlopen') as network:
                bootstrap.download('https://example.invalid/archive', path, hashlib.sha256(b'verified').hexdigest())
            network.assert_not_called()

    def test_unverified_jdk_cannot_be_exposed_to_setup_java(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / 'github-output'
            output.write_text('existing=value\n', encoding='utf-8')
            with patch.object(bootstrap, 'ROOT', root), \
                    patch.object(sys, 'argv', ['bootstrap.py', 'jdk-archive']), \
                    patch.dict(bootstrap.os.environ, {'GITHUB_OUTPUT': str(output)}), \
                    patch.object(bootstrap, 'download', side_effect=ValueError('Official archive checksum mismatch')):
                self.assertEqual(bootstrap.main(), 1)
            self.assertEqual(output.read_text(encoding='utf-8'), 'existing=value\n')
            self.assertEqual(len(list((root / 'artifacts/phase6').glob('*/bootstrap-failure.json'))), 1)

    def test_snapshot_excludes_private_runtime_inputs(self):
        for name in ('.env', '.env.vuln002', 'artifacts/raw.json', 'dashboard/backend/.venv/file', 'apps/vulnerable-app/src/main/Foo.java'):
            self.assertFalse(snapshot.allowed(name))
        self.assertTrue(snapshot.allowed('scripts/phase6/ci.py'))

    def test_linux_lock_preserves_every_sealed_pin(self):
        original=(bootstrap.ROOT/'scanners/semgrep/requirements.lock.txt').read_text().splitlines()
        adapter=(bootstrap.ROOT/'scripts/phase6/semgrep-linux.lock.txt').read_text().splitlines()
        actual=[line.split(';',1)[0].strip() for line in adapter if line and not line.startswith('#')]
        self.assertEqual(actual,[line for line in original if line and not line.startswith('#')])
        self.assertIn('pywin32==311; sys_platform == "win32"',adapter)
