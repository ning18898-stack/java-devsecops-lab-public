"""Export reviewed working files into a newly initialized repository; copy no Git history."""
import hashlib
import json
from pathlib import Path
import sys
import uuid

sys.path.insert(0, str(Path(__file__).parent))
from ci import ROOT, DOCS, LEGAL_FILES, Run, git, write_json


def allowed(name):
    return name in DOCS | LEGAL_FILES or name.startswith((
        'scripts/phase6/', '.github/workflows/', 'docs/ci/', 'docs/delivery/',
        'docs/portfolio/', 'docs/diagrams/', 'reports/examples/')) or name in {
        'docs/validation/phase6-validation.md', 'docs/validation/phase6-summary.json'}


def main():
    manifest = ROOT / 'docs/release/source-manifest.json'
    sys.path.insert(0, str(Path(__file__).parents[1] / 'public_release'))
    from integrity import verify, source_revision, source_tree
    if manifest.exists():
        verify(ROOT)
        names = git('ls-files').splitlines()
    else:
        if (ROOT / 'apps').exists():
            raise ValueError('An application snapshot requires its reviewed public manifest')
        changes = git('diff', '--name-only', 'HEAD').splitlines() + git('ls-files', '--others', '--exclude-standard').splitlines()
        if any(not allowed(name) for name in changes):
            raise ValueError('Out-of-scope synthetic fixture overlay')
        names = git('ls-files').splitlines() + changes
    run = Run(ROOT / 'artifacts/phase6')
    target = ROOT / 'artifacts/phase6-clean' / ('checkout-' + uuid.uuid4().hex[:12])
    target.mkdir(parents=True)
    hashes = {}
    for name in sorted(set(names)):
        source = ROOT / name
        if not source.is_file() or source.is_symlink():
            raise ValueError('Invalid snapshot source: ' + name)
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = source.read_bytes()
        if source.suffix != '.png':
            content = content.replace(b'\r\n', b'\n')
        destination.write_bytes(content)
        hashes[name] = hashlib.sha256(content).hexdigest()
    run.command(['git', 'init', '-q', '-b', 'main', str(target)], 'independent-git-init')
    policy_path = ROOT / 'docs/release/publishing-identity.json'
    if policy_path.exists():
        policy = json.loads(policy_path.read_text(encoding='utf-8'))
        for key, value in (('user.name', policy['username']), ('user.email', policy['noreply']),
                           ('user.useConfigOnly', 'true'), ('commit.gpgsign', 'false'), ('core.autocrlf', 'false')):
            run.command(['git', '-C', str(target), 'config', '--local', key, value], 'independent-identity')
    run.command(['git', '-C', str(target), 'add', '--all'], 'independent-index')
    if manifest.exists():
        source_tree(target)
    for name in ('.tools', '.env', 'dashboard/backend/.venv', 'dashboard/frontend/node_modules'):
        if (target / name).exists():
            raise ValueError('Snapshot inherited runtime state')
    write_json(run.path / 'snapshot.json', {'status': 'PASS', 'target': str(target),
        'base_revision': source_revision(ROOT), 'overlay_sha256': hashes,
        'runtime_state': 'absent', 'history': 'none; independently initialized'})
    print(target)
    return 0


if __name__ == '__main__':
    sys.exit(main())
