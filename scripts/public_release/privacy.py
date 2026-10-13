"""Public file and Git identity checks; private historical identities are never embedded here."""
import json
from pathlib import Path
import re
import struct
import subprocess


def check(root):
    root = Path(root).resolve()
    policy = json.loads((root / 'docs/release/publishing-identity.json').read_text(encoding='utf-8'))
    names = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard'], cwd=root).decode().splitlines()
    rejected = []
    synthetic_paths = {
        'dashboard/backend/tests/test_api.py': {'C:/Users/secret'},
        'scripts/phase6/tests/test_delivery.py': {'C:/Users/person/secret'},
        'scripts/public_release/privacy.py': {'C:/Users/secret', 'C:/Users/person/secret'},
    }
    path_pattern = re.compile(r'''[A-Za-z]:[\\/](?:Users|home)[\\/][^\s"']+''')
    key_pattern = re.compile(r'-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{30,}|\bsk-proj-[A-Za-z0-9_-]{20,}')
    reviewed_images = 0
    for name in set(names):
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ValueError('Invalid public file: ' + name)
        if re.search(r'(^|/)(\.git|\.env(?!\.example)|node_modules|target|\.venv)(/|$)|\.(sqlite3|pem|key|jar|exe|zip)$', name):
            rejected.append(name)
        raw = path.read_bytes()
        if path.suffix == '.png':
            if raw[:8] != b'\x89PNG\r\n\x1a\n':
                rejected.append(name)
            offset = 8
            while offset + 12 <= len(raw):
                length = struct.unpack('>I', raw[offset:offset+4])[0]
                kind = raw[offset+4:offset+8]
                if kind in (b'tEXt', b'iTXt', b'zTXt', b'eXIf'):
                    raise ValueError('Image metadata requires explicit review: ' + name)
                offset += length + 12
            reviewed_images += 1
            continue
        text = raw.decode('utf-8')
        if re.search(r'\b[A-Za-z0-9.+_-]+@gmail\.com\b', text, re.I) or key_pattern.search(text):
            rejected.append(name)
        if set(path_pattern.findall(text)) - synthetic_paths.get(name, set()):
            rejected.append(name)
        for repository in re.findall(r'https://github\.com/' + re.escape(policy['username']) + r'/([^/\s)]+)', text):
            if repository != 'java-devsecops-lab-public':
                rejected.append(name)
    if rejected:
        raise ValueError('Public privacy check rejected: ' + ', '.join(sorted(set(rejected))))
    if (root / '.git/objects/info/alternates').exists():
        raise ValueError('Unexpected external Git linkage in local public candidate')
    for remote in subprocess.check_output(['git', 'remote'], cwd=root).decode().splitlines():
        urls = subprocess.check_output(['git', 'remote', 'get-url', '--all', remote], cwd=root).decode().splitlines()
        repository = policy['username'] + '/java-devsecops-lab-public'
        allowed = {'https://github.com/' + repository, 'https://github.com/' + repository + '.git',
                   'git@github.com:' + repository, 'git@github.com:' + repository + '.git'}
        if not urls or any(url not in allowed for url in urls):
            raise ValueError('Remote must point only to the independent public repository')
    objects = subprocess.check_output(['git', 'cat-file', '--batch-all-objects', '--batch-check=%(objectname) %(objecttype)'], cwd=root).decode().splitlines()
    count = 0
    for record in objects:
        oid, kind = record.split()
        if kind not in ('commit', 'tag'): continue
        text = subprocess.check_output(['git', 'cat-file', '-p', oid], cwd=root).decode('utf-8')
        if re.search(r'\b[A-Za-z0-9.+_-]+@gmail\.com\b', text, re.I) or key_pattern.search(text) or path_pattern.search(text):
            raise ValueError('Git object contains private-looking text')
        for label in (('author', 'committer') if kind == 'commit' else ('tagger',)):
            expected = label + ' ' + policy['username'] + ' <' + policy['noreply'] + '> '
            if not any(line.startswith(expected) for line in text.splitlines()):
                raise ValueError('Git object uses an unapproved identity')
        count += 1
    return {'status': 'PASS', 'files': len(set(names)), 'git_identity_objects': count, 'images_without_text_metadata': reviewed_images,
            'synthetic_rejection_paths': 'explicitly allowed test-only values', 'scope': 'configured patterns and actual Git identities; images manually reviewed'}
