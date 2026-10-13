"""Install pinned local teaching tools. No global PATH or credential changes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("record", ROOT / "scripts/phase3-command.py")
record = importlib.util.module_from_spec(spec)
spec.loader.exec_module(record)
run = record.run
VERSION = "2.27.2"
SHA256 = "6c90c8503af7b13827a151fbada959c1e5e4a49dd4ebad5bf0855f8a54404c1b"


def main():
    tools = ROOT / ".tools"
    archive = tools / f"codeql-win64-{VERSION}.zip"
    if os.name != "nt":
        raise RuntimeError("This bootstrap is Windows-only; see scanners/README.md")
    if not archive.exists() or hashlib.file_digest(archive.open("rb"), "sha256").hexdigest() != SHA256:
        run(["curl.exe", "-fL", "--retry", "3", "--connect-timeout", "20", "--speed-limit", "1000", "--speed-time", "30", "-C", "-",
             f"https://github.com/github/codeql-cli-binaries/releases/download/v{VERSION}/codeql-win64.zip",
             "-o", str(archive)], "download-codeql")
    actual = hashlib.file_digest(archive.open("rb"), "sha256").hexdigest()
    if actual != SHA256:
        raise RuntimeError("CodeQL release checksum mismatch")
    destination = tools / f"codeql-{VERSION}"
    if not (destination / "codeql/codeql.exe").exists():
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(destination)
    run([str(destination / "codeql/codeql.exe"), "version", "--format=json"], "codeql-version")
    python = tools / "semgrep/Scripts/python.exe"
    if not python.exists():
        run([sys.executable, "-m", "venv", str(tools / "semgrep")], "create-semgrep-venv")
    lock = ROOT / "scanners/semgrep/requirements.lock.txt"
    run([str(python), "-m", "pip", "install", "-r", str(lock)] if lock.exists()
        else [str(python), "-m", "pip", "install", "semgrep==1.180.0"], "install-semgrep")
    run([str(tools / "semgrep/Scripts/semgrep.exe"), "--version"], "semgrep-version")
    record.OUT.joinpath("setup-result.json").write_text(json.dumps({"codeql": VERSION,
        "sha256": actual, "semgrep": "1.180.0", "status": "PASS"}, indent=2))


if __name__ == "__main__":
    main()
