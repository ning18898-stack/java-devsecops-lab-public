"""Install exactly the reviewed official images. Pulls are installation, never target scans."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from labscan.core import ROOT, Run, load_json, write_json


def main():
    run = Run()
    lock = load_json(ROOT / "scanners/zap/images.lock.json")
    try:
        for name in ("zap", "java", "python"):
            run.command(["docker", "pull", lock[name]], "install-" + name, timeout=600, retries=1)
        run.command(["docker", "run", "--rm", "--network=none", lock["java"], "java", "-version"], "container-java-version", timeout=60)
        run.command(["docker", "run", "--rm", "--network=none", lock["python"], "python", "--version"], "container-python-version", timeout=60)
        run.command(["docker", "run", "--rm", "--network=none", lock["zap"], "zap.sh", "-version"], "container-zap-version", timeout=90)
        write_json(run.path / "installation.json", {"status": "PASS", "images": lock})
        return 0
    except Exception as error:
        write_json(run.path / "installation.json", {"status": "FAILED", "failure": str(error)})
        return 1


if __name__ == '__main__':
    sys.exit(main())
