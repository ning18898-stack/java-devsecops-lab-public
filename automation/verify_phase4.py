"""Actual full Gate. READY is false until every required independent check succeeds."""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from labscan.core import ROOT, Run, credentials, load_json, now, sha, verify_evidence, write_json
from labscan.results import validate_report
from labscan.workflow import execute, phase3, preflight, protected
from labscan.zap import Sandbox


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    gate = Run()
    summary = {"PHASE4_READY": False, "status": "FAILED", "started": now(), "run_id": gate.id,
               "source_revision": __import__('labscan.core', fromlist=['source_identity']).source_identity()[0],
               "Ubuntu": "NOT_TESTED"}
    mysql = False
    try:
        protected(gate)
        gate.command([sys.executable, "-m", "unittest", "discover", "-s", "automation/tests", "-v"], "unit-tests", timeout=120)
        versions, lock = preflight(gate, ["semgrep", "codeql", "zap"])
        summary["tool_versions"] = versions
        # Actual boundary probes are restricted to the new project's own isolated gateway.
        sandbox = Sandbox(gate, lock)
        try:
            sandbox.start()
            sandbox.verify()
            probe = """import http.client,json
address='ADDRESS'
cases=[('GET','/actuator/health',address+':8080',200),('GET','/%61ctuator/health',address+':8080',502),
('GET','//actuator/health',address+':8080',502),('GET','/api/labs/vuln002/articles/1',address+':8080',502),
('GET','/actuator/health?x=1',address+':8080',502),('GET','/actuator/health','foreign:8080',502),
('POST','/api/articles',address+':8080',403),('CONNECT','example.com:443',address+':8080',403)]
for method,path,host,expected in cases:
    c=http.client.HTTPConnection(address,8080,timeout=5)
    c.request(method,path,headers={'Host':host}); r=c.getresponse(); r.read()
    assert r.status==expected,(method,path,r.status)
    c.close()
print(json.dumps({'boundary_probes':len(cases),'status':'PASS'}))
""".replace("ADDRESS", sandbox.address)
            gate.command(["docker", "exec", sandbox.guard, "python", "-c", probe], "live-boundary-probes", timeout=60)
            summary["boundary"] = "PASS"
        finally:
            sandbox.close()
        dry, dry_report = execute(["semgrep", "codeql", "zap"], dry_run=True)
        check(dry_report["execution_status"] == "NOT_EXECUTED", "Dry run incorrectly marked scan success")
        summary["dry_run"] = dry.id
        first, report = execute(["semgrep", "codeql", "zap"])
        check(report["execution_status"] == "COMPLETED", "Actual all-tool run failed: " + first.id)
        validate_report(report)
        verify_evidence(first.path, report["evidence_manifest"])
        summary["scan_run_id"] = first.id
        counts = {s["tool"]: s["finding_count"] for s in report["steps"]}
        check(counts["semgrep"] == 2 and counts["codeql"] == 3, "Static integration differs from sealed contracts")
        summary["observations"] = counts
        # A child run must keep the parent's full evidence untouched, explicitly reuse static results,
        # revalidate a new dynamic target, and associate fingerprints across ephemeral endpoints.
        before = {p.relative_to(first.path).as_posix(): sha(p) for p in first.path.rglob('*') if p.is_file()}
        second, repeated = execute(["semgrep", "codeql", "zap"], resume=first.id, correlate_with=first.id)
        check(repeated["execution_status"] == "COMPLETED", "Resume/repeat run failed")
        check(all(s["execution_mode"] == "historical-reuse" for s in repeated["steps"][:2]), "Static reuse not explicit")
        check(repeated["steps"][2]["execution_mode"] == "actual-execution", "ZAP scan was not rerun")
        check({f["fingerprint"] for f in report["findings"]} == {f["fingerprint"] for f in repeated["findings"]}, "Unstable observation identity")
        check(all(f["correlation"] == "previously-observed" for f in repeated["findings"]), "Correlation failure")
        check(before == {p.relative_to(first.path).as_posix(): sha(p) for p in first.path.rglob('*') if p.is_file()}, "History overwritten")
        summary["repeat_run_id"] = second.id
        module = phase3(gate)
        # Existing test suites and dedicated MySQL setup; protected implementation reused unchanged.
        mysql = True
        summary["regressions"] = module.builds()
        protected(gate)
        gate.command(["git", "diff", "--check"], "diff-check", timeout=30)
        candidates = [p for directory in (gate.path, dry.path, first.path, second.path)
                      for p in directory.rglob('*') if p.is_file() and p.suffix in ('.log', '.json', '.jsonl', '.sarif', '.yaml', '.xml')]
        for path in candidates:
            text = path.read_text(encoding='utf-8', errors='replace')
            check(not any(secret in text for secret in credentials() if len(secret) >= 8), "Credential leak in " + path.name)
        summary["credential_hygiene"] = {"status": "PASS", "files_checked": len(candidates)}
        summary.update(PHASE4_READY=True, status="PASS", exit_code=0)
    except (Exception, KeyboardInterrupt) as error:
        summary["failure"] = str(error)
        summary["exit_code"] = 1
        gate.event({"gate_failure": str(error)})
    finally:
        if mysql:
            try:
                gate.command(["docker", "compose", "--env-file", str(ROOT / ".env.vuln002"), "-f",
                              "labs/VULN-002-IDOR/compose.yml", "stop"], "mysql-stop", timeout=120)
            except Exception as error:
                summary.update(PHASE4_READY=False, status="FAILED", exit_code=1, cleanup_failure=str(error))
        summary["ended"] = now()
        write_json(gate.path / "gate.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    return summary["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
