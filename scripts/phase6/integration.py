"""Reuse the sealed real HTTP, restart, proxy and three browser tests, with new evidence."""
import importlib.util
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from ci import ROOT, Run, materialize, write_json, git


def main():
    if os.name != "nt":
        raise ValueError("The sealed Edge integration Gate requires Windows")
    materialize()
    spec = importlib.util.spec_from_file_location("p6_p5_http", ROOT / "dashboard/verify_phase5.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    run = Run(ROOT / "artifacts/phase6")
    run.save = lambda name, data: (run.path / name).write_text(__import__('json').dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    from labscan.core import now
    started = now()
    result = {"status": "FAIL"}
    code = 1
    try:
        result = module.http_acceptance(run)
        code = 0
        return 0
    except Exception as error:
        result["failure"] = str(error)
        raise
    finally:
        result.update(run_id=run.id, started=started, ended=now(), exit_code=code,
                      source_revision=git("rev-parse", "HEAD"), commands=run.commands, environment=sys.platform)
        write_json(run.path / "integration.json", result)


if __name__ == "__main__":
    sys.exit(main())
