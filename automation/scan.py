"""Unified local CLI: python automation/scan.py [scan|preflight|boundary]."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from labscan.boundary import TARGET
from labscan.core import Run
from labscan.workflow import execute, preflight, protected
from labscan.zap import Sandbox


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("scan", "preflight", "boundary"), nargs="?", default="scan")
    parser.add_argument("--tool", choices=("all", "semgrep", "codeql", "zap"), default="all")
    parser.add_argument("--target", default=TARGET, help="Fixed authorized project identity, no arbitrary URL")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", help="Verified previous run ID; new immutable child run")
    parser.add_argument("--correlate-with", help="Verified prior run ID for observation association")
    parser.add_argument("--retries", type=int, choices=range(3), default=1)
    args = parser.parse_args()
    tools = ["semgrep", "codeql", "zap"] if args.tool == "all" else [args.tool]
    if args.action == "scan":
        _, report = execute(tools, args.dry_run, args.target, args.resume, args.correlate_with, args.retries)
        return 0 if report["execution_status"] in ("COMPLETED", "NOT_EXECUTED") and not report["failure"] else 1
    run = Run()
    try:
        protected(run)
        if args.target != TARGET:
            raise ValueError("Unauthorized target")
        _, lock = preflight(run, tools)
        if args.action == "boundary" and not args.dry_run:
            sandbox = Sandbox(run, lock)
            try:
                sandbox.start()
                sandbox.verify()
            finally:
                sandbox.close()
        run.event({"action": args.action, "status": "NOT_EXECUTED" if args.dry_run else "COMPLETED"})
        print("run_id=" + run.id, flush=True)
        return 0
    except Exception as error:
        run.event({"failure": str(error)})
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
