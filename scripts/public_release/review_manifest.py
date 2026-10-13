"""Explicit maintainer-reviewed rebaseline; never called by CI."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from privacy import check

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--reviewed', action='store_true', required=True,
                        help='Confirm that changes, attribution and example provenance have been manually reviewed')
    parser.parse_args()
    check(ROOT)
    names = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard'], cwd=ROOT).decode().splitlines()
    files = {}
    for name in names:
        if name in ('docs/release/source-manifest.json', 'docs/release/local-validation.json'): continue
        path = ROOT / name
        raw = path.read_bytes()
        files[name] = hashlib.sha256(raw if path.suffix == '.png' else raw.replace(b'\r\n', b'\n')).hexdigest()
    data = {'schema_version': 1, 'provenance': 'Explicitly reviewed public source snapshot; no private history seal', 'files': files}
    (ROOT / 'docs/release/source-manifest.json').write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n', encoding='utf-8', newline='\n')
    print('Reviewed public manifest written; obtain fresh validation evidence before publishing')


if __name__ == '__main__':
    main()
