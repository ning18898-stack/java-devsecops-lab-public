import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[2] / 'public_release'))
import privacy

POLICY = json.loads((Path(__file__).parents[3] / 'docs/release/publishing-identity.json').read_text(encoding='utf-8'))


class PublicPrivacyTests(unittest.TestCase):
    def fixture(self, root):
        subprocess.check_call(['git', 'init', '-q', '-b', 'main', str(root)])
        (root / 'docs/release').mkdir(parents=True)
        (root / 'docs/release/publishing-identity.json').write_text(json.dumps(POLICY), encoding='utf-8')
        (root / 'source.py').write_text('print("fixture")\n', encoding='utf-8')
        subprocess.check_call(['git', 'add', '--all'], cwd=root)

    def test_public_remote_allowed_but_foreign_remote_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            url = 'https://github.com/' + POLICY['username'] + '/java-devsecops-lab-public.git'
            subprocess.check_call(['git', 'remote', 'add', 'origin', url], cwd=root)
            self.assertEqual(privacy.check(root)['status'], 'PASS')
            subprocess.check_call(['git', 'remote', 'set-url', 'origin', 'https://example.invalid/foreign.git'], cwd=root)
            with self.assertRaises(ValueError): privacy.check(root)

    def test_unapproved_git_identity_rejected_without_creating_real_bad_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            original = subprocess.check_output
            def output(arguments, **kwargs):
                if '--batch-all-objects' in arguments:
                    return ('0'*40 + ' commit\n').encode()
                if arguments[:3] == ['git', 'cat-file', '-p']:
                    return b'author Untrusted <fixture@example.invalid> 1 +0000\ncommitter Untrusted <fixture@example.invalid> 1 +0000\n'
                return original(arguments, **kwargs)
            with patch.object(privacy.subprocess, 'check_output', side_effect=output):
                with self.assertRaises(ValueError): privacy.check(root)


if __name__ == '__main__':
    unittest.main()
