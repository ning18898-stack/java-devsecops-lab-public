import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))
import snapshot
import verify


class ReleasePreparationTests(unittest.TestCase):
    def test_legal_overlay_survives_clean_snapshot_and_changes_resume_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def git(*args):
                return subprocess.check_output(['git', *args], cwd=root).decode().strip()

            git('init', '-q')
            (root / 'README.md').write_text('isolated fixture\n', encoding='utf-8')
            (root / '.gitignore').write_text('artifacts/\n', encoding='utf-8')
            git('add', 'README.md', '.gitignore')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                'commit', '-qm', 'fixture')
            with patch.object(verify, 'ROOT', root):
                before = verify.fingerprint()
                for name in ('LICENSE', 'NOTICE'):
                    (root / name).write_text('test placeholder; no license granted\n', encoding='utf-8')
                added = verify.fingerprint()
                self.assertNotEqual(before, added)
                (root / 'LICENSE').write_text('changed test placeholder\n', encoding='utf-8')
                changed = verify.fingerprint()
                self.assertNotEqual(added, changed)
                git('add', 'LICENSE')
                self.assertEqual(changed, verify.fingerprint())
            with patch.object(snapshot, 'ROOT', root), patch.object(snapshot, 'git', git), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(snapshot.main(), 0)
            manifest = json.loads(next((root / 'artifacts/phase6').glob('*/snapshot.json')).read_text())
            target = Path(manifest['target'])
            for name in ('LICENSE', 'NOTICE'):
                expected = (root / name).read_bytes().replace(b'\r\n', b'\n')
                self.assertEqual((target / name).read_bytes(), expected)
                self.assertEqual(manifest['overlay_sha256'][name],
                                 hashlib.sha256(expected).hexdigest())

    def test_legal_allowlist_keeps_sealed_and_private_paths_rejected(self):
        for name in ('LICENSE', 'NOTICE'):
            self.assertTrue(snapshot.allowed(name))
        for name in ('LICENSE.key', '.env', 'legal/private.txt', 'apps/secure-app/LICENSE',
                     'apps/vulnerable-app/src/main/Foo.java', 'scanners/codeql/queries/Foo.ql'):
            self.assertFalse(snapshot.allowed(name))


if __name__ == '__main__':
    unittest.main()
