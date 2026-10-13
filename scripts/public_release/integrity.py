"""Integrity of an independently exported public snapshot, without private Git seals."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def source_tree(root=ROOT):
    root = Path(root).resolve()
    top = Path(subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], cwd=root).decode().strip()).resolve()
    if top != root or (root / '.git/objects/info/alternates').exists():
        raise ValueError('Source tree must belong to an independent public checkout')
    with tempfile.TemporaryDirectory() as temporary:
        env = dict(os.environ, GIT_INDEX_FILE=str(Path(temporary) / 'source-index'))
        subprocess.check_call(['git', 'add', '--', 'apps/vulnerable-app/src/main', 'apps/secure-app/src/main'], cwd=root, env=env)
        tree = subprocess.check_output(['git', 'write-tree'], cwd=root, env=env).decode().strip()
    subprocess.check_call(['git', 'update-ref', 'refs/snapshots/public-source-v1', tree], cwd=root)
    return tree


def source_revision(root=ROOT):
    root = Path(root).resolve()
    top = Path(subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], cwd=root).decode().strip()).resolve()
    if top != root or (root / '.git/objects/info/alternates').exists():
        raise ValueError('Source identity must belong to an independent public checkout')
    result = subprocess.run(['git', 'rev-parse', '--verify', 'HEAD'], cwd=root, capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip()
    # An unborn local candidate uses its independently written Git tree, which has no author/tagger.
    return subprocess.check_output(['git', 'write-tree'], cwd=root).decode().strip()


def verify(root=ROOT):
    root = Path(root).resolve()
    top = Path(subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], cwd=root).decode().strip()).resolve()
    if top != root or (root / '.git/objects/info/alternates').exists():
        raise ValueError('Public checkout is not independent')
    manifest = json.loads((root / 'docs/release/source-manifest.json').read_text(encoding='utf-8'))
    names = set(subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard'], cwd=root).decode().splitlines())
    exceptions = {'docs/release/source-manifest.json', 'docs/release/local-validation.json'}
    if names - exceptions != set(manifest['files']):
        raise ValueError('Public snapshot file set changed')
    for name, expected in manifest['files'].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root) or path.is_symlink() or not path.is_file():
            raise ValueError('Invalid manifest path')
        raw = path.read_bytes()
        actual = hashlib.sha256(raw if path.suffix == '.png' else raw.replace(b'\r\n', b'\n')).hexdigest()
        if actual != expected:
            raise ValueError('Public snapshot changed: ' + name)
    return {'status': 'PASS', 'count': len(manifest['files']), 'files': manifest['files'],
            'provenance': 'Independently reviewed public source snapshot; no historical phase seals'}
