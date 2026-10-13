"""Final local acceptance for SQL injection and IDOR; no target arguments."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "labs/VULN-002-IDOR"))
import db
import runtime as rt

OUTPUT = ROOT / "artifacts/phase2"
DOCS = {"PROJECT.md", "TASKS.md", "README.md", "docs/architecture.md",
        "docs/validation/phase2-validation.md", "scripts/verify-phase2.py"}


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT).decode("utf-8")


def run(args, label, env=None):
    start = datetime.now(timezone.utc).isoformat()
    code = 1
    try:
        with (OUTPUT / (label + ".log")).open("w", encoding="utf-8") as log:
            code = subprocess.run(args, cwd=ROOT, env=env, stdout=log,
                                  stderr=subprocess.STDOUT, timeout=1200).returncode
    finally:
        with (OUTPUT / "commands.jsonl").open("a", encoding="utf-8") as log:
            log.write(json.dumps({"command": args, "label": label, "started": start,
                "ended": datetime.now(timezone.utc).isoformat(), "exit_code": code}) + "\n")
    print(f"{label}: exit code {code}", flush=True)
    if code:
        raise RuntimeError("Command failed: " + label)


def integrity():
    return public_integrity()


def documents_and_secrets():
    # Inspect only the implemented applications, lab tooling, infrastructure and documentation.
    names = set(git("ls-files", "--", "apps", "infra", "labs", "scripts", "docs",
                    "PROJECT.md", "TASKS.md", "README.md", ".gitignore").splitlines()) | DOCS
    secrets = []
    for name in (".env", ".env.vuln001", ".env.vuln002"):
        for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                if key.endswith("PASSWORD") and value:
                    secrets.append(value)
        if subprocess.run(["git", "check-ignore", "-q", "--", name], cwd=ROOT).returncode:
            raise AssertionError("Credentials not ignored")
        if git("ls-files", "--", name).strip():
            raise AssertionError("Credentials tracked")
    paths = [ROOT / name for name in sorted(names)]
    paths += list(OUTPUT.glob("*.log")) + list(OUTPUT.glob("*.json*"))
    paths += [p for p in (ROOT / "artifacts").glob("vuln00*-*") if p.is_file()]
    paths += list((ROOT / "artifacts").glob("vuln002-*-reports/TEST-*.xml"))
    links = 0
    for path in paths:
        content = path.read_text(encoding="utf-8", errors="replace")
        if any(secret in content for secret in secrets):
            raise AssertionError("Local credential found; values suppressed")
        if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
                     r"sk-proj-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}", content):
            raise AssertionError("Credential-shaped material found; values suppressed")
        if path.suffix == ".md":
            for link in re.findall(r"\[[^\]]*\]\(([^)]+)\)", content):
                if "://" not in link and not link.startswith("#"):
                    if not (path.parent / link.split("#", 1)[0]).exists():
                        raise AssertionError("Broken documentation link")
                    links += 1
    if subprocess.run(["git", "check-ignore", "-q", "--", "artifacts/phase2/result.json"], cwd=ROOT).returncode:
        raise AssertionError("Evidence not ignored")
    return {"files_checked": len(paths), "local_links": links, "credentials": "PASS"}


def jars():
    hashes = {}
    for variant in ("vulnerable", "secure"):
        path = ROOT / f"apps/{variant}-app/target/{variant}-app-0.1.0-SNAPSHOT.jar"
        with zipfile.ZipFile(path) as jar:
            if any("h2-" in name or "application-test.yml" in name or "application-mysql-test.yml" in name
                   for name in jar.namelist()):
                raise AssertionError("Test runtime in production JAR")
            classes = [name for name in jar.namelist()
                       if name.startswith("BOOT-INF/classes/com/example/") and name.endswith(".class")]
            if not classes or any(int.from_bytes(jar.read(name)[6:8], "big") != 61 for name in classes):
                raise AssertionError("JAR requires Java 17")
        hashes[variant] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def isolation():
    env = rt.environment()
    compose = ["docker", "compose", "--env-file", ".env.vuln001", "-f",
               "labs/VULN-001-SQL-Injection/compose.yml", "--profile", "vuln001"]
    cid = subprocess.check_output([*compose, "ps", "-q", "mysql"], cwd=ROOT).decode().strip()
    if not re.fullmatch(r"[a-f0-9]{12,64}", cid):
        raise AssertionError("Dedicated SQLi container required")
    mysql_env = dict(os.environ, MYSQL_PWD=env["VULN001_DB_PASSWORD"])
    def sql(statement, denied=False):
        response = subprocess.run(["docker", "exec", "-i", "-e", "MYSQL_PWD", cid, "mysql",
            "--protocol=TCP", "-h127.0.0.1", "-uvuln001_reader", "--batch", "--raw",
            "--skip-column-names", "lab_vuln001"], input=statement, env=mysql_env,
            capture_output=True, text=True, encoding="utf-8", timeout=20)
        if denied:
            if response.returncode == 0 or not re.search(r"ERROR (1044|1142|1143) ", response.stderr):
                raise AssertionError("SQLi account access denial required")
        elif response.returncode:
            raise AssertionError("SQLi fixture inspection failed")
        return response.stdout.strip()
    expected = "1\tAlpha public article\tpublic\n2\tBeta public article\tpublic\n3\tSynthetic draft article\tdraft"
    before = sql("SELECT id,title,visibility FROM lab_articles ORDER BY id;")
    if before != expected:
        raise AssertionError("SQLi fixtures differ from the synthetic seed")
    grants = sql("SHOW GRANTS;").splitlines()
    if len(grants) != 2 or not any("GRANT USAGE ON *.*" in grant for grant in grants) or not any(
            "GRANT SELECT ON `lab_vuln001`.`lab_articles`" in grant for grant in grants):
        raise AssertionError("SQLi grants must be USAGE and table SELECT only")
    sql("UPDATE lab_articles SET title=title WHERE id=1;", denied=True)
    sql("SELECT * FROM lab_test.app_users;", denied=True)
    if sql("SELECT id,title,visibility FROM lab_articles ORDER BY id;") != before:
        raise AssertionError("Fixture inspection mutated data")
    ports = {}
    for variant, container in (("sqli", cid), ("idor", db.compose("ps", "-q", "mysql").strip())):
        bindings = json.loads(subprocess.check_output(["docker", "inspect", "--format",
            "{{json .NetworkSettings.Ports}}", container], cwd=ROOT))
        exposed = [binding for entries in bindings.values() if entries for binding in entries]
        expected_port = "13308" if variant == "sqli" else "13309"
        if exposed != [{"HostIp": "127.0.0.1", "HostPort": expected_port}]:
            raise AssertionError("Only the dedicated loopback database port may be exposed")
        ports[variant] = expected_port
    return {"sqli_synthetic_rows": 3, "sqli_readonly_and_cross_schema_denial": "PASS",
            "loopback_ports": ports}


def main():
    if len(sys.argv) != 1:
        raise ValueError("No target or mode arguments accepted")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    result = {"started": datetime.now(timezone.utc).isoformat(), "status": "FAIL", "exit_code": 1,
              "scope": ["VULN-001 SQL Injection", "VULN-002 IDOR"]}
    try:
        result["integrity"] = integrity()
        run([sys.executable, "-m", "unittest", "discover", "-s", "labs/VULN-001-SQL-Injection",
             "-p", "test_verify.py", "-v"], "sqli-python-tests")
        run([sys.executable, "-u", "labs/VULN-002-IDOR/acceptance.py"], "combined-acceptance")
        combined = json.loads((ROOT / "artifacts/vuln002-acceptance-result.json").read_text(encoding="utf-8"))
        if combined["status"] != "PASS" or combined["exit_code"] != 0 or combined["started"] < result["started"]:
            raise AssertionError("Fresh completed acceptance required")
        result["acceptance"] = combined
        result["sqli"] = json.loads((ROOT / "artifacts/vuln001-poc-result.json").read_text(encoding="utf-8"))
        if result["sqli"]["exit_code"] != 0:
            raise AssertionError("SQL injection regression failed")
        result["jars_sha256"] = jars()
        result["isolation"] = isolation()
        result["integrity"] = integrity()
        result["review"] = documents_and_secrets()
        run(["git", "diff", "--check"], "diff-check")
        result.update(status="PASS", exit_code=0)
    except Exception as error:
        result["error_type"] = type(error).__name__
        raise
    finally:
        result["ended"] = datetime.now(timezone.utc).isoformat()
        (OUTPUT / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("Phase 2 final acceptance PASS; exit code 0", flush=True)


def public_integrity():
    sys.path.insert(0, str(ROOT / 'scripts/public_release'))
    from integrity import verify
    return verify(ROOT)

if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Phase 2 acceptance FAIL {type(error).__name__}; inspect ignored logs; exit code 1")
        sys.exit(1)

