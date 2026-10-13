"""Record one local Phase 3 command; never turn a tool error into success."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/phase3"


def run(command, label, env=None, cwd=ROOT, timeout=1800):
    OUT.mkdir(parents=True, exist_ok=True)
    start = datetime.now(timezone.utc).isoformat()
    log = OUT / (label + "-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f") + ".log")
    code, failure = 1, None
    try:
        with log.open("w", encoding="utf-8") as output:
            code = subprocess.run(command, cwd=cwd, env=env, stdout=output,
                                  stderr=subprocess.STDOUT, timeout=timeout).returncode
        if code:
            failure = "Nonzero exit; see full output log"
    except Exception as error:
        failure = str(error)
        with log.open("a", encoding="utf-8") as output:
            output.write("\nRunner failure: " + failure + "\n")
    record = {"label": label, "command": list(map(str, command)), "cwd": str(cwd),
              "started": start, "ended": datetime.now(timezone.utc).isoformat(),
              "exit_code": code, "failure": failure, "output": str(log)}
    with (OUT / "commands.jsonl").open("a", encoding="utf-8") as output:
        output.write(json.dumps(record) + "\n")
    print(f"{label}: exit={code}; {log}", flush=True)
    # Convenient pointer copy; immutable timestamped logs retain every attempt.
    import shutil
    shutil.copy2(log, OUT / (label + ".log"))
    if code:
        raise RuntimeError(f"{label}: {failure}")
    return log


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("label")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        run(args.command, args.label)
    except RuntimeError as error:
        print(error, file=sys.stderr)
        sys.exit(1)
