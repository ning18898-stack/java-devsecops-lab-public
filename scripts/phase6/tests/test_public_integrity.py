import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[2] / 'public_release'))
import integrity


class PublicIntegrityTests(unittest.TestCase):
    def fixture(self, root):
        subprocess.check_call(['git', 'init', '-q', '-b', 'main', str(root)])
        (root / 'source.py').write_bytes(b'print("fixture")\n')
        (root / 'docs/release').mkdir(parents=True)
        (root / 'docs/release/source-manifest.json').write_text(json.dumps({'files': {
            'source.py': hashlib.sha256((root / 'source.py').read_bytes()).hexdigest()}}), encoding='utf-8')
        subprocess.check_call(['git', 'add', '--all'], cwd=root)

    def test_unborn_candidate_has_independent_tree_and_no_commit_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            self.assertEqual(integrity.verify(root)['count'], 1)
            revision = integrity.source_revision(root)
            self.assertEqual(subprocess.check_output(['git', 'cat-file', '-t', revision], cwd=root).decode().strip(), 'tree')
            self.assertEqual(subprocess.run(['git', 'rev-parse', '--verify', 'HEAD'], cwd=root, capture_output=True).returncode, 128)

    def test_modified_deleted_and_unlisted_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            source = root / 'source.py'
            original = source.read_bytes()
            source.write_bytes(b'changed\n')
            with self.assertRaises(ValueError): integrity.verify(root)
            source.unlink()
            with self.assertRaises(ValueError): integrity.verify(root)
            source.write_bytes(original)
            (root / 'unexpected.txt').write_text('unexpected', encoding='utf-8')
            with self.assertRaises(ValueError): integrity.verify(root)

    def test_parent_repository_and_external_objects_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            child = root / 'child'
            child.mkdir()
            with self.assertRaises(ValueError): integrity.source_revision(child)
            with self.assertRaises(ValueError): integrity.verify(child)
            alternate = root / '.git/objects/info/alternates'
            alternate.write_text('/untrusted/objects', encoding='utf-8')
            with self.assertRaises(ValueError): integrity.source_revision(root)
            with self.assertRaises(ValueError): integrity.verify(root)


if __name__ == '__main__':
    unittest.main()
