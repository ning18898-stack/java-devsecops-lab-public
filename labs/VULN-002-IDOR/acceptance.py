"""Repeatable local build, HTTP evidence and final MySQL regression."""
from datetime import datetime, timezone
import json
import shutil
import sys
import uuid
import xml.etree.ElementTree as ET
import auth_verify
import db
import manage
import runtime as rt
import verify


def reports(variant, label, profile, expected):
    directory = db.ROOT / f"apps/{variant}-app/target/surefire-reports"
    totals = dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)
    for path in directory.glob("TEST-*.xml"):
        suite = ET.parse(path).getroot()
        for name in totals:
            totals[name] += int(suite.attrib[name])
        properties = {item.attrib["name"]: item.attrib["value"] for item in suite.find("properties")}
        if not properties["java.version"].startswith("17.") or properties["spring.profiles.active"] != profile:
            raise AssertionError("JUnit reports use unexpected Java or profile")
    if totals != {"tests": expected, "failures": 0, "errors": 0, "skipped": 0}:
        raise AssertionError("Full regression test counts do not match acceptance")
    destination = db.ROOT / "artifacts" / ("vuln002-" + label + "-reports")
    destination.mkdir(exist_ok=True)
    for path in directory.glob("TEST-*.xml"):
        shutil.copy2(path, destination / path.name)
    print(f"{label}: {expected} tests PASS; Java 17; profile {profile}", flush=True)
    return totals


def default_http():
    rt.command([sys.executable, "scripts/verify-baseline.py"], "default-baseline-http")
    client = rt.Client("vulnerable")
    client.token = client.request("GET", "/api/auth/csrf", 200)["token"]
    name, password = "off_" + uuid.uuid4().hex[:12], uuid.uuid4().hex
    client.request("POST", "/api/auth/register", 201,
        {"username": name, "email": name + "@example.test", "password": password})
    client.request("POST", "/api/auth/login", 200, {"username": name, "password": password}, form=True)
    client.token = client.request("GET", "/api/auth/csrf", 200)["token"]
    for lab in ("vuln001", "vuln002"):
        client.request("GET", "/api/labs/" + lab + "/info", 404)
        rt.Client("secure").request("GET", "/api/labs/" + lab + "/info", 404)
    client.request("POST", "/api/auth/logout", 200)
    print("Default JARs: both lab routes disabled; baseline HTTP PASS; exit code 0", flush=True)


def main():
    if len(sys.argv) != 1:
        raise ValueError("No target or mode arguments accepted")
    started = datetime.now(timezone.utc).isoformat()
    summary = {"started": started, "status": "RUNNING", "exit_code": 1}
    output = db.ROOT / "artifacts/vuln002-acceptance-result.json"
    output.parent.mkdir(exist_ok=True)
    try:
        manage.manage("up")
        # Restore only the existing VULN-001 read-only fixtures; no volume reset.
        rt.command(["docker", "compose", "--env-file", ".env.vuln001", "-f",
            "labs/VULN-001-SQL-Injection/compose.yml", "--profile", "vuln001", "up", "-d", "--wait", "--wait-timeout", "180"],
            "vuln001-up", timeout=240)
        rt.command([sys.executable, "-m", "unittest", "discover", "-s", "labs/VULN-002-IDOR", "-p", "test_*.py"], "python-tests")
        summary["rapid_tests"] = {}
        for variant, expected in (("vulnerable", 81), ("secure", 41)):
            label = "rapid-" + variant
            rt.maven(variant, label, "clean", "package")
            summary["rapid_tests"][variant] = reports(variant, label, "test", expected)
        with rt.Servers(mode="default", label="default"):
            default_http()
        with rt.Servers(mode="vuln001,vuln002", label="enabled"):
            auth_verify.verify()
            summary["poc"] = [verify.verify("poc-first"), verify.verify("poc-repeat")]
            rt.command([sys.executable, "scripts/verify-baseline.py"], "enabled-baseline-http")
            rt.command([sys.executable, "labs/VULN-001-SQL-Injection/verify.py"], "vuln001-regression")
        summary["mysql_tests"] = {}
        for variant, expected in (("vulnerable", 81), ("secure", 41)):
            label = "final-mysql-" + variant
            rt.maven(variant, label, "-Pmysql", "test")
            summary["mysql_tests"][variant] = reports(variant, label, "mysql-test", expected)
        summary.update(status="PASS", exit_code=0)
    except Exception as error:
        summary.update(status="FAIL", error_type=type(error).__name__)
        raise
    finally:
        summary["ended"] = datetime.now(timezone.utc).isoformat()
        output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print("VULN-002 complete local acceptance PASS; exit code 0", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"VULN-002 acceptance FAIL {type(error).__name__}; inspect ignored logs; exit code 1", flush=True)
        sys.exit(1)
