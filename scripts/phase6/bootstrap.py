"""Install pinned delivery dependencies locally; CodeQL installation remains explicit."""
import argparse
import hashlib
import os
from pathlib import Path
import sys
import tarfile
import urllib.request
import zipfile

sys.path.insert(0, str(Path(__file__).parent))
from ci import ROOT, Run, write_json

ACTIONLINT = {
    "windows_amd64.zip": "6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9",
    "linux_amd64.tar.gz": "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
}


def download(url, path, digest):
    if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        with urllib.request.urlopen(url, timeout=60) as response:
            path.write_bytes(response.read())
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise ValueError("Official archive checksum mismatch")


def install():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("dashboard", "semgrep", "actionlint", "linux-runtimes", "jdk-archive"))
    args = parser.parse_args()
    run = Run(ROOT / "artifacts/phase6")
    global ACTIVE_RUN
    ACTIVE_RUN = run
    if args.mode == "jdk-archive":
        if os.name == "nt":
            asset = "OpenJDK17U-jdk_x64_windows_hotspot_17.0.20.1_1.zip"
            digest = "e53a79c3c3d86865bd7e787903884331068e71321714ffd44f145785affc7cb0"
        elif sys.platform == "linux":
            asset = "OpenJDK17U-jdk_x64_linux_hotspot_17.0.20.1_1.tar.gz"
            digest = "3808d1d15e3ec6bd5b84057fb5d84c33d8a1536a258146bcea2e603fc726e08e"
        else:
            raise ValueError("Hosted JDK archive supports Windows/Linux x64 only")
        folder = ROOT / ".tools"
        folder.mkdir(exist_ok=True)
        archive = folder / asset
        download("https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20.1%2B1/" + asset,
                 archive, digest)
        if os.environ.get("GITHUB_OUTPUT"):
            with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
                output.write("archive=.tools/" + asset + "\n")
    elif args.mode == "linux-runtimes":
        if os.name == "nt":
            raise ValueError("Run linux-runtimes in native Ubuntu")
        folder = ROOT / ".tools"
        folder.mkdir(exist_ok=True)
        archives = [
            ("https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20.1%2B1/OpenJDK17U-jdk_x64_linux_hotspot_17.0.20.1_1.tar.gz",
             "3808d1d15e3ec6bd5b84057fb5d84c33d8a1536a258146bcea2e603fc726e08e"),
            ("https://nodejs.org/dist/v24.12.0/node-v24.12.0-linux-x64.tar.xz",
             "bdebee276e58d0ef5448f3d5ac12c67daa963dd5e0a9bb621a53d1cefbc852fd"),
        ]
        for url, digest in archives:
            archive = folder / url.rsplit("/", 1)[1]
            download(url, archive, digest)
            with tarfile.open(archive) as bundle:
                bundle.extractall(folder, filter="data")
        run.command([folder / "jdk-17.0.20.1+1/bin/java", "-version"], "java-version")
        run.command([folder / "node-v24.12.0-linux-x64/bin/node", "--version"], "node-version")
    elif args.mode == "actionlint":
        suffix = "windows_amd64.zip" if os.name == "nt" else "linux_amd64.tar.gz"
        folder = ROOT / ".tools/actionlint-1.7.12"
        folder.mkdir(parents=True, exist_ok=True)
        archive = folder.parent / ("actionlint_1.7.12_" + suffix)
        download("https://github.com/rhysd/actionlint/releases/download/v1.7.12/" + archive.name,
                 archive, ACTIONLINT[suffix])
        if os.name == "nt":
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(folder)
        else:
            with tarfile.open(archive) as bundle:
                bundle.extractall(folder, filter="data")
        run.command([folder / ("actionlint.exe" if os.name == "nt" else "actionlint"), "-version"], "actionlint-version")
    else:
        folder = ROOT / ("dashboard/backend/.venv" if args.mode == "dashboard" else ".tools/semgrep")
        python = folder / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if not python.exists():
            run.command([sys.executable, "-m", "venv", folder], "venv-create")
        lock = "dashboard/backend/requirements.txt" if args.mode == "dashboard" else (
            "scanners/semgrep/requirements.lock.txt" if os.name == "nt" else "scripts/phase6/semgrep-linux.lock.txt")
        run.command([python, "-m", "pip", "install", "-r", lock], "locked-dependencies", timeout=900)
        run.command([python, "-m", "pip", "check"], "dependency-check")
    write_json(run.path / "bootstrap.json", {"status": "PASS", "mode": args.mode, "commands": run.commands})
    return 0


def main():
    try:
        return install()
    except Exception as error:
        from labscan.core import now, redact
        run = globals().get('ACTIVE_RUN') or Run(ROOT/'artifacts/phase6')
        write_json(run.path/'bootstrap-failure.json',{'status':'FAIL','mode':sys.argv[1:],
            'ended':now(),'exit_code':1,'failure':redact(str(error),run.secrets),'commands':run.commands})
        print('Bootstrap failed; see preserved Phase6 evidence',file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
