"""Run sealed MySQL setup with Phase 4 immutable logs, preserving older helper logs."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from labscan.core import ROOT, Run, write_json


def main():
    run = Run()
    sys.path.insert(0, str(ROOT / "labs/VULN-002-IDOR"))
    import runtime
    import manage
    def recorded(args, label, env=None, timeout=300):
        return run.command(args, label, env or runtime.environment(), timeout=timeout)
    runtime.command = recorded
    try:
        manage.manage("up")
        write_json(run.path / "regression-setup.json", {"status": "PASS", "run_id": run.id,
                    "implementation": "sealed labs/VULN-002-IDOR/manage.py; command recording replaced in memory"})
        return 0
    except Exception as error:
        run.event({"failure": str(error)})
        return 1


if __name__ == '__main__':
    sys.exit(main())
