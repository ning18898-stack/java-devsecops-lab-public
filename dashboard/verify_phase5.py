"""Actual independent Gate; unique directories preserve failures and intermediate evidence."""
from datetime import datetime, timezone
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / "dashboard/backend/.venv/Scripts/python.exe"
NODE = shutil.which("node")
NPM = shutil.which("npm.cmd")
sys.path.insert(0, str(ROOT / "automation/src"))
from labscan.core import now, redact, credentials
from labscan.workflow import TAGS

REAL_ID = "release-example-001"
DOCS = {"PROJECT.md", "TASKS.md", "docs/architecture.md"}


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


class Gate:
    def __init__(self):
        self.id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:12]
        self.path = ROOT / "artifacts/phase5" / self.id
        self.path.mkdir(parents=True)
        self.commands = []

    def save(self, name, data):
        (self.path / name).write_text(json.dumps(redact(data, credentials()), ensure_ascii=False, indent=2), encoding="utf-8")

    def command(self, args, label, env=None, timeout=1800, cwd=None):
        record = {"label": label, "command": list(map(str, args)), "started": now()}
        print(f"START {label}", flush=True)
        try:
            result = subprocess.run(list(map(str, args)), cwd=cwd or ROOT, env=env, capture_output=True, timeout=timeout)
            text = (result.stdout + result.stderr).decode("utf-8", errors="replace")
            record["exit_code"] = result.returncode
        except subprocess.TimeoutExpired as exc:
            text = ((exc.stdout or b"") + (exc.stderr or b"")).decode("utf-8", errors="replace")
            record["exit_code"] = 124
        record["ended"] = now()
        (self.path / f"{label}-{len(self.commands)}.log").write_text(redact(text, credentials()), encoding="utf-8")
        self.commands.append(record)
        self.save("commands.json", self.commands)
        print(f"END {label} exit={record['exit_code']}", flush=True)
        check(record["exit_code"] == 0, f"{label} failed; see preserved log")
        return text

    def protected(self):
        result = public_integrity()
        self.save("protected-files.json", result)
        return result


def original_evidence():
    return {p.relative_to(ROOT).as_posix(): sha256(p.read_bytes()).hexdigest()
            for p in (ROOT / "reports/examples").rglob("*") if p.is_file()}


def http_acceptance(gate):
    import httpx
    for port in (5173, 18765):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
    env = dict(os.environ, DASHBOARD_DB=str(gate.path / "integration.sqlite3"),
               DASHBOARD_IMPORT_ROOT=str(ROOT / "artifacts/phase4"), DASHBOARD_API="http://127.0.0.1:18765",
               P5_EVIDENCE_DIR=str(gate.path / "browser"))
    (gate.path / "browser").mkdir()
    handles = []
    processes = []
    records = []
    def start_backend():
        handle = (gate.path / f"backend-service-{len(handles)}.log").open("w", encoding="utf-8")
        handles.append(handle)
        process = subprocess.Popen([str(PYTHON), str(ROOT / "dashboard/backend/serve.py"), "--port", "18765"], cwd=ROOT, env=env, stdout=handle, stderr=handle, creationflags=subprocess.CREATE_NO_WINDOW)
        processes.append(process)
        return process
    client = httpx.Client(base_url="http://127.0.0.1:18765", timeout=30)
    def request(method, path, body=None, expected=200):
        response = client.request(method, "/api" + path, json=body)
        records.append({"method": method, "path": path, "status": response.status_code, "timestamp": now()})
        gate.save("http.json", records)
        check(response.status_code == expected, f"HTTP {path} expected {expected}, got {response.status_code}")
        return response.json()
    def ready():
        for _ in range(100):
            try:
                if client.get("/api/health").status_code == 200:
                    check(processes[-1].poll() is None, "Started process exited")
                    return
            except httpx.HTTPError:
                pass
            time.sleep(.2)
        raise RuntimeError("Service not ready")
    try:
        backend = start_backend()
        ready()
        check(request("GET", "/summary")["runs"] == 0, "Test database must be independent")
        request("POST", "/imports", {"run_id": REAL_ID}, expected=403)
        client.headers["x-dashboard-token"] = request("GET", "/session")["write_token"]
        check(request("POST", "/imports", {"run_id": REAL_ID})["imported"], "Actual import")
        check(not request("POST", "/imports", {"run_id": REAL_ID})["imported"], "Actual idempotency")
        run = request("GET", "/runs/" + REAL_ID)
        check({s["tool"]: s["finding_count"] for s in run["steps"]} == {"semgrep": 2, "codeql": 3, "zap": 0}, "Real input counts")
        rows = request("GET", "/findings")["items"]
        fid = rows[0]["id"]
        detail = request("GET", f"/findings/{fid}")
        request("GET", f"/evidence/{detail['observations'][0]['evidence'][0]['id']}")
        detail = request("POST", f"/findings/{fid}/status", {"status": "confirmed", "version": 1, "note": "Phase 5 HTTP 隔离验收：按封存实验报告研判"})
        request("POST", f"/findings/{fid}/notes", {"note": "Phase 5 HTTP 隔离验收：持久化与重启检查"})
        detail = request("GET", f"/findings/{fid}")
        check(len(detail["history"]) == 3 and detail["status"] == "confirmed", "Actual audit")
        request("POST", f"/findings/{fid}/status", {"status": "closed", "version": detail["version"], "note": "测试拒绝无证据关闭"}, expected=409)
        request("GET", "/findings?page=0", expected=422)
        backend.terminate()
        backend.wait(timeout=15)
        start_backend()
        ready()
        persisted = request("GET", f"/findings/{fid}")
        check(persisted["history"] == detail["history"] and persisted["status"] == "confirmed", "Actual restart persistence")
        client.headers["x-dashboard-token"] = request("GET", "/session")["write_token"]
        request("POST", "/imports", {"run_id": REAL_ID})
        handle = (gate.path / "vue-service.log").open("w", encoding="utf-8")
        handles.append(handle)
        frontend = subprocess.Popen([NODE, str(ROOT / "dashboard/frontend/node_modules/vite/bin/vite.js"), "--host", "127.0.0.1", "--port", "5173", "--strictPort"], cwd=ROOT / "dashboard/frontend", env=env, stdout=handle, stderr=handle, creationflags=subprocess.CREATE_NO_WINDOW)
        processes.append(frontend)
        for _ in range(100):
            try:
                if httpx.get("http://127.0.0.1:5173", timeout=2).status_code == 200:
                    check(frontend.poll() is None, "Started Vue exited")
                    break
            except httpx.HTTPError:
                pass
            time.sleep(.2)
        else:
            raise RuntimeError("Vue not ready")
        proxy = httpx.get("http://127.0.0.1:5173/api/summary", timeout=10)
        check(proxy.status_code == 200 and proxy.json()["observations"] == 5, "Vue actual proxy integration")
        gate.command([NPM, "run", "test:e2e"], "browser-e2e", env, cwd=ROOT / "dashboard/frontend", timeout=300)
        return {"status": "PASS", "actual_http_requests": len(records), "restart": "PASS", "real_input": REAL_ID, "browser": "Microsoft Edge", "database": "independent integration.sqlite3"}
    finally:
        client.close()
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
        for handle in handles:
            handle.close()


def regressions(gate):
    spec = importlib.util.spec_from_file_location("sealed_phase3_p5", ROOT / "scripts/verify-phase3.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.OUT = gate.path
    from regression_setup import start
    def recorded(command, label, env=None, **kwargs):
        if list(map(str, command)) == [sys.executable, "labs/VULN-002-IDOR/manage.py", "up"]:
            start(gate.command)
            return "sealed MySQL setup executed with Phase 5 logs"
        return gate.command(command, label, env, **kwargs)
    module.run = recorded
    try:
        return module.builds()
    finally:
        gate.command(["docker", "compose", "--env-file", ROOT / ".env.vuln002", "-f", "labs/VULN-002-IDOR/compose.yml", "stop"], "mysql-stop", timeout=120)


def main():
    gate = Gate()
    summary = {"PHASE5_READY": False, "status": "FAILED", "run_id": gate.id, "started": now(), "source_revision": __import__("labscan.core", fromlist=["source_identity"]).source_identity()[0]}
    print(f"GATE {gate.path}", flush=True)
    try:
        check(sys.platform == "win32", "Full Gate currently validates Windows only")
        implementation = {name: sha256(ROOT.joinpath(name).read_bytes()).hexdigest()
                          for name in git("ls-files", "--cached", "--others", "--exclude-standard", "dashboard").decode().splitlines()
                          if not name.startswith("dashboard/docs/") and name != "dashboard/README.md"}
        gate.save("implementation.json", implementation)
        summary["protected"] = gate.protected()
        before = original_evidence()
        gate.save("phase4-evidence-before.json", before)
        gate.command([PYTHON, "-m", "pip", "check"], "python-dependencies")
        gate.command([PYTHON, "-m", "pytest", "dashboard/backend/tests", "-q", "--junitxml=" + str(gate.path / "backend.xml")], "backend-tests", timeout=240)
        summary["P5-01_P5-02_P5-04"] = "PASS"
        gate.save("progress.json", summary)
        gate.command([NPM, "ci"], "frontend-dependencies", cwd=ROOT / "dashboard/frontend", timeout=240)
        gate.command([NPM, "run", "test"], "frontend-tests", cwd=ROOT / "dashboard/frontend", timeout=180)
        gate.command([NPM, "run", "build"], "frontend-build", cwd=ROOT / "dashboard/frontend", timeout=120)
        summary["P5-03"] = "PASS"
        summary["integration"] = http_acceptance(gate)
        gate.save("progress.json", summary)
        gate.command([sys.executable, "-m", "unittest", "discover", "-s", "automation/tests", "-v"], "automation-regression", timeout=120)
        gate.command([sys.executable, "-m", "unittest", "discover", "-s", "scanners/zap/tests", "-v"], "zap-regression", timeout=120)
        summary["regressions"] = regressions(gate)
        gate.save("progress.json", summary)
        check(before == original_evidence(), "Original Phase 4 artifacts changed")
        summary["phase4_evidence_unchanged"] = len(before)
        summary["protected"] = gate.protected()
        gate.command(["git", "diff", "--check"], "diff-check", timeout=30)
        check(all(ROOT.joinpath(name).is_file() and sha256(ROOT.joinpath(name).read_bytes()).hexdigest() == digest
                  for name, digest in implementation.items()), "Implementation changed while Gate was running")
        candidates = [p for p in gate.path.rglob("*") if p.is_file() and p.suffix in (".json", ".log", ".xml")]
        for path in candidates:
            text = path.read_text(encoding="utf-8", errors="replace")
            check(not any(s in text for s in credentials() if len(s) >= 8), "Credential leak: " + path.name)
        summary.update(PHASE5_READY=True, status="PASS", exit_code=0, sensitive_log_check="PASS")
    except (Exception, KeyboardInterrupt) as exc:
        summary.update(exit_code=1, failure=str(exc))
    summary["ended"] = now()
    gate.save("gate.json", summary)
    (ROOT / "artifacts/phase5/latest.json").write_text(json.dumps({"run_id": gate.id, "path": str(gate.path)}), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    return summary["exit_code"]


def public_integrity():
    sys.path.insert(0, str(ROOT / 'scripts/public_release'))
    from integrity import verify
    return verify(ROOT)

if __name__ == "__main__":
    sys.exit(main())

