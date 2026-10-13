"""Phase 6 delivery adapter. Sealed implementations and assertions stay unchanged."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "automation/src"))
from labscan.core import Run, credentials, load_json, now, redact, sha, write_json

SEALED = None
TAGS = {}
TAG_OBJECTS = {}
DOCS = {"README.md", "PROJECT.md", "TASKS.md", "docs/architecture.md", "docs/environment.md"}
LEGAL_FILES = {"LICENSE", "NOTICE"}
FIXTURES = ROOT / "reports/examples/phase4-reviewed"
IDS = ("release-example-001",
       "release-example-002")


def git(*args):
    if args == ('rev-parse', 'HEAD'):
        sys.path.insert(0, str(ROOT / 'scripts/public_release'))
        from integrity import source_revision
        return source_revision(ROOT)
    return subprocess.check_output(["git", *args], cwd=ROOT).decode().strip()


def environment():
    env = dict(os.environ, PYTHONUTF8="1", SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
    jdk = env.get("JAVA_HOME") or str(ROOT / ".tools/jdk17/jdk-17.0.20.1+1")
    env.update(JAVA_HOME=jdk, PATH=str(Path(jdk) / "bin") + os.pathsep + env["PATH"])
    if os.name != "nt":
        env['PATH'] = str(Path(jdk)/'bin') + ':/usr/local/bin:/usr/bin:/bin:' + env['PATH']
    for key in list(env):
        if key.startswith(("VULN001_", "VULN002_", "SPRING_PROFILES_")) or key == "SEMGREP_APP_TOKEN":
            env.pop(key, None)
    return env


def maven(variant, *args):
    wrapper = ROOT / "apps/vulnerable-app" / ("mvnw.cmd" if os.name == "nt" else "mvnw")
    prefix = ["cmd.exe", "/d", "/c"] if os.name == "nt" else ["sh"]
    return [*prefix, str(wrapper), "-B", "-ntp", "-f", str(ROOT / f"apps/{variant}-app/pom.xml"), *args]


def materialize():
    # Fresh public clones receive no custom Git refs. Rebuild the safe snippet tree from source.
    sys.path.insert(0, str(ROOT / 'scripts/public_release'))
    from integrity import source_tree
    manifest = load_json(FIXTURES / "manifest.json")
    for name, digest in manifest["files"].items():
        path = (FIXTURES / name).resolve()
        if not path.is_relative_to(FIXTURES.resolve()) or sha(path) != digest:
            raise ValueError("Reviewed fixture integrity failure")
    for run_id in IDS:
        target = ROOT / "artifacts/phase4" / run_id
        if target.exists():
            if not (target / "report.json").is_file():
                raise ValueError("Incomplete existing input; refusing overwrite")
            continue  # Preserve actual historical evidence on the developer's machine.
        snippet_tree = source_tree(ROOT)
        if load_json(FIXTURES / run_id / 'report.json')['source_revision'] != snippet_tree:
            raise ValueError('Demonstration source snapshot differs; explicit fixture review required')
        shutil.copytree(FIXTURES / run_id, target)
    return {"status": "PASS", "provenance": manifest["provenance"], "runs": list(IDS)}


def mysql_init_override(run):
    if sys.platform == "win32":
        return []
    if sys.platform != "linux":
        raise ValueError("MySQL delivery adapter supports Windows/Linux only")
    # Linux checkouts keep the sealed script at 0644. Execute an identical copy
    # in its own shell so its `set -u` cannot leak into MySQL's entrypoint.
    directory = run.path / "mysql-init"
    directory.mkdir()
    source = ROOT / "infra/mysql/vuln002-init/001-init.sh"
    script = directory / source.name
    script.write_bytes(source.read_bytes().replace(b"\r\n", b"\n"))
    script.chmod(0o755)
    override = run.path / "mysql-init.override.json"
    write_json(override, {"services": {"mysql": {"volumes": [
        {"type": "bind", "source": str(directory.resolve()),
         "target": "/docker-entrypoint-initdb.d", "read_only": True}]}}})
    return ["-f", str(override)]


@contextmanager
def mysql(run):
    """Fresh project/volume and random credentials; never reuse developer databases."""
    sys.path.insert(0, str(ROOT / "labs/VULN-002-IDOR"))
    import db
    import runtime
    keys = {key: secrets.token_hex(24) for key in db.KEYS}
    keys.update(VULN001_DB_PASSWORD=secrets.token_hex(24), VULN001_ROOT_PASSWORD=secrets.token_hex(24))
    run.secrets.extend(keys.values())
    project = "p6-" + run.id[-12:]
    envfile = run.path / "mysql.env"
    envfile.write_text("".join(f"{key}={value}\n" for key, value in keys.items()), encoding="utf-8")
    if os.name != "nt":
        envfile.chmod(0o600)
    prefix = ["docker", "compose", "--project-name", project, "--env-file", str(envfile),
              "-f", str(ROOT / "labs/VULN-002-IDOR/compose.yml"), *mysql_init_override(run)]
    sql1 = ["docker", "compose", "--project-name", project + "-sqli", "--env-file", str(envfile),
            "-f", str(ROOT / "labs/VULN-001-SQL-Injection/compose.yml"), "--profile", "vuln001"]
    old_credentials, old_compose = db.credentials, db.compose
    old_subprocess = db.subprocess
    def database_command(*args, **kwargs):
        started = now()
        result = subprocess.run(*args, **kwargs)
        with (run.path/'mysql-diagnostics.jsonl').open('a',encoding='utf-8') as stream:
            stream.write(json.dumps({'started':started,'ended':now(),'exit_code':result.returncode,
                'stderr':redact(result.stderr or '',run.secrets)})+'\n')
        return result
    db.subprocess = SimpleNamespace(run=database_command)
    old_path = os.environ['PATH']
    if os.name != 'nt':
        # Prefer the native Docker CLI over Docker Desktop's Windows-interoperability shim.
        os.environ['PATH'] = '/usr/local/bin:/usr/bin:/bin:' + old_path
    db.credentials = lambda create=False: keys
    db.compose = lambda *args, timeout=180: run.command([*prefix, *args], "mysql-helper", timeout=timeout).read_text().strip()
    try:
        run.command([*prefix, "config", "--quiet"], "mysql-config")
        run.command([*prefix, "up", "-d", "--wait", "--wait-timeout", "180"], "mysql-up", timeout=240)
        cid=db.compose('ps','-q','mysql')
        if not re.fullmatch(r'[a-f0-9]{12,64}',cid):
            raise ValueError('Invalid isolated container identifier')
        for _ in range(60):
            # The image's temporary initialization server can satisfy a socket healthcheck.
            # Require the final TCP server before the sealed helper's socket operations.
            run.command(['docker','exec','-e','MYSQL_PWD',cid,'mysql','--protocol=TCP','-h127.0.0.1','-uroot','-e','SELECT VERSION()'],
                'mysql-final-readiness',dict(os.environ,MYSQL_PWD=keys['VULN002_ROOT_PASSWORD']),timeout=20,accepted=(0,1))
            if run.commands[-1]['exit_code']==0:break
            time.sleep(.5)
        else:
            raise TimeoutError('Final isolated MySQL TCP server not ready')
        db.regression_database()
        db.isolation()
        run.command([*sql1, "up", "-d", "--wait", "--wait-timeout", "180"], "mysql-sqli-up", timeout=240)
        env = environment()
        for key in ("VULN002_APP_PASSWORD", "VULN002_MANAGER_PASSWORD", "VULN002_READER_PASSWORD"):
            env[key] = keys[key]
        env.update(TEST_DB_URL="jdbc:mysql://127.0.0.1:13309/lab_test?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true",
                   TEST_DB_USERNAME="v002_regression", TEST_DB_PASSWORD=keys["VULN002_MANAGER_PASSWORD"])
        env.update(VULN001_TEST_DB_URL="jdbc:mysql://127.0.0.1:13308/lab_vuln001?allowMultiQueries=false&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true",
                   VULN001_TEST_DB_USERNAME="vuln001_reader", VULN001_TEST_DB_PASSWORD=keys["VULN001_DB_PASSWORD"])
        yield env
    except Exception:
        # Capture bounded, redacted initialization diagnostics before disposable cleanup.
        try:
            run.command([*prefix, "logs", "--no-color", "--tail", "100", "mysql"],
                        "mysql-failure-logs", timeout=30, accepted=(0, 1))
        except Exception:
            pass  # Preserve the original failure even if Docker diagnostics are unavailable.
        raise
    finally:
        db.credentials, db.compose, db.subprocess = old_credentials, old_compose, old_subprocess
        try:
            # The exact unique project is fixed here, with only this run's disposable volume.
            try:
                run.command([*sql1, "down", "--volumes"], "mysql-sqli-cleanup", timeout=120)
            finally:
                run.command([*prefix, "down", "--volumes"], "mysql-cleanup", timeout=120)
        finally:
            envfile.unlink(missing_ok=True)
            os.environ['PATH'] = old_path


def java(run):
    result = {}
    run.command(maven("vulnerable", "-version"), "maven-version", environment())
    with mysql(run) as env:
        for variant, count in (("vulnerable", 81), ("secure", 41)):
            result[variant] = {}
            for profile, args in (("quick", ["clean", "package"]), ("mysql", ["-Pmysql", "test"])):
                test_env = dict(env)
                if profile == "quick":
                    for key in ("VULN001_TEST_DB_URL", "VULN001_TEST_DB_USERNAME", "VULN001_TEST_DB_PASSWORD"):
                        test_env.pop(key, None)
                run.command(maven(variant, *args), f"java-{variant}-{profile}", test_env)
                totals = dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)
                dest = run.path / f"junit-{variant}-{profile}"
                dest.mkdir()
                for path in ROOT.joinpath(f"apps/{variant}-app/target/surefire-reports").glob("TEST-*.xml"):
                    suite = ET.parse(path).getroot()
                    props = {p.attrib["name"]: p.attrib["value"] for p in suite.find("properties")}
                    if not props["java.version"].startswith("17."):
                        raise ValueError("Expected JDK 17")
                    for key in totals:
                        totals[key] += int(suite.attrib[key])
                    shutil.copy2(path, dest / path.name)
                if totals != {"tests": count, "failures": 0, "errors": 0, "skipped": 0}:
                    raise ValueError("Sealed test contract failed: " + variant)
                result[variant][profile] = totals
    return result


def python_tests(run):
    for directory, pattern in (("automation/tests", "test*.py"), ("scripts", "test_phase3.py"),
                               ("labs/VULN-001-SQL-Injection", "test*.py"), ("labs/VULN-002-IDOR", "test*.py"),
                               ("scripts/phase6/tests", "test*.py")):
        run.command([sys.executable, "-m", "unittest", "discover", "-s", directory, "-p", pattern, "-v"],
                    "python-" + directory.replace("/", "-"), environment(), timeout=180)
    return {"status": "PASS", "framework": "stdlib unittest", "dependencies": "none"}


def backend(run):
    materialize()
    run.command([sys.executable, "-m", "pip", "check"], "backend-dependencies")
    run.command([sys.executable, "-m", "pytest", "dashboard/backend/tests", "-q",
                 "--junitxml=" + str(run.path / "backend.xml")], "backend-tests", timeout=240)
    suites = ET.parse(run.path / "backend.xml").getroot()
    totals = {key: sum(int(s.attrib.get(key, 0)) for s in suites.findall("testsuite"))
              for key in ("tests", "failures", "errors", "skipped")}
    if totals != {"tests":51, "failures":0, "errors":0, "skipped":0}:
        raise ValueError("Full sealed backend suite required")
    return {"status": "PASS", "totals":totals, "storage": "pytest tmp_path", "input": "reviewed historical derivatives on clean checkout"}


def frontend(run):
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    cwd = ROOT / "dashboard/frontend"
    run.command([shutil.which("node"), "--version"], "node-version")
    run.command([npm, "--version"], "npm-version")
    run.command([npm, "ci"], "npm-ci", cwd=cwd, timeout=300)
    run.command([npm, "run", "test", "--", "--reporter=default", "--reporter=junit",
                 "--outputFile=" + str(run.path / "frontend.xml")], "vue-tests", cwd=cwd)
    run.command([npm, "run", "build"], "vue-build", cwd=cwd)
    suites = ET.parse(run.path / "frontend.xml").getroot()
    if sum(int(s.attrib.get("tests",0)) for s in suites.findall("testsuite")) != 7:
        raise ValueError("Full sealed frontend suite required")
    return {"status": "PASS", "tests": 7, "production_build": "PASS"}


def phase3(run):
    spec = importlib.util.spec_from_file_location("p6_phase3", ROOT / "scripts/verify-phase3.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.OUT = run.path
    module.JDK = Path(environment()["JAVA_HOME"])
    module.environment = environment
    module.SEMGREP = Path(shutil.which("semgrep") or ROOT / (".tools/semgrep/Scripts/semgrep.exe" if os.name=='nt' else ".tools/semgrep/bin/semgrep"))
    module.CODEQL = Path(shutil.which("codeql") or ROOT / ".tools/codeql-2.27.2/codeql/codeql.exe")
    module.run = run.command
    return module


def semgrep(run):
    return phase3(run).semgrep()


def codeql(run):
    # Fresh databases, original queries, extraction scope and path assertions.
    if os.name != "nt":
        raise ValueError("CodeQL delivery adapter currently requires Windows")
    return phase3(run).codeql(rebuild=True)


def zap(run):
    from labscan.zap import Sandbox
    lock = load_json(ROOT / "scanners/zap/images.lock.json")
    for key in ("zap", "java", "python"):
        run.command(["docker", "pull", lock[key]], "pull-" + key, timeout=900)
    original = run.command
    def adapted(command, label, env=None, **kwargs):
        if label == "app-runtime-build":
            env = environment()
            if os.name != "nt":
                command = ["sh", str(ROOT / "apps/vulnerable-app/mvnw"), *command[4:]]
        if label == "zap-create" and os.name != "nt":
            # Only this disposable output directory; ZAP's fixed container UID may differ from runner UID.
            (run.path / "zap-work").chmod(0o777)
        return original(command, label, env, **kwargs)
    run.command = adapted
    sandbox = Sandbox(run, lock)
    try:
        sandbox.start()
        # scan_zap performs and records its own write-once pre-scan verification.
        report, address = sandbox.scan_zap()
        from labscan.results import parse_zap
        observations = parse_zap(load_json(report), "zap.json", git("rev-parse", "HEAD"), run.id, address)
        shutil.copy2(report, run.path / "zap.json")
        return {"status": "PASS", "mode": "passive-baseline", "requests": 5,
                "active_scan": False, "observations": len(observations)}
    finally:
        sandbox.close()
        run.command = original


def hygiene(run):
    sys.path.insert(0, str(ROOT / 'scripts/public_release'))
    from integrity import verify
    from privacy import check
    privacy_result = check(ROOT)
    integrity = verify(ROOT)
    checked = list(integrity['files'])
    tags = {}
    names = set(git("ls-files", "--cached", "--others", "--exclude-standard").splitlines())
    links = 0
    for name in names:
        if re.search(r"(^|/)(\.env(?!\.example)|node_modules|target|\.venv)(/|$)|\.(sqlite3|pem|key)$", name):
            raise ValueError("Forbidden delivery artifact: " + name)
        path = ROOT / name
        content = path.read_text(encoding="utf-8", errors="replace")
        if any(value in content for value in credentials() if len(value) >= 8):
            raise ValueError("Actual credential in delivery file: " + name)
        if re.search(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{30,}|\bsk-proj-[A-Za-z0-9_-]{20,}", content):
            raise ValueError("Credential-like content: " + name)
        if path.suffix == ".md":
            for link in re.findall(r"\[[^\]]*\]\(([^)]+)\)", content):
                if "://" not in link and not link.startswith("#"):
                    if not (path.parent / link.split("#", 1)[0]).exists():
                        raise ValueError("Broken local document link: " + name + ": " + link)
                    links += 1
        if name.startswith("reports/examples/") and re.search(r"[A-Za-z]:[\\/]|/home/|/mnt/[a-z]/", content):
            raise ValueError("Personal path in public sample: " + name)
    run.command(["git", "diff", "--check"], "diff-check")
    return {"status": "PASS", "protected_files": len(checked), "tags": tags,
            "delivery_files": len(names), "local_links": links, "credential_scan": "known values + key patterns",
            "public_privacy": privacy_result}


def workflows(run):
    lock = load_json(ROOT / "docs/ci/actions.lock.json")
    files = sorted(ROOT.joinpath(".github/workflows").glob("*.yml"))
    for path in files:
        content = path.read_text()
        if "pull_request_target" in content or "secrets." in content or "contents: write" in content:
            raise ValueError("Unexpected privileged workflow")
        for repo, commit in re.findall(r"uses:\s+actions/([a-z-]+)@([a-f0-9]+)", content):
            if len(commit) != 40 or lock[repo]["commit"] != commit:
                raise ValueError("Unreviewed Action commit")
    executable = Path(os.environ.get("ACTIONLINT_PATH", ROOT / ".tools/actionlint-1.7.12" / ("actionlint.exe" if os.name == "nt" else "actionlint")))
    run.command([executable, "-version"], "actionlint-version")
    run.command([executable, "-shellcheck=", "-pyflakes=", *files], "workflow-lint")
    return {"status": "PASS", "files": len(files), "actionlint": "1.7.12",
            "scope": "syntax, expressions, types, Action inputs; inline commands exercised locally; hosted execution NOT_TESTED"}


def publish(run):
    """Explicit allowlist, structure-preserving redaction; no databases/logs/traces."""
    dest = ROOT / "artifacts/phase6-public" / run.id
    dest.mkdir(parents=True)
    paths = [run.path / "result.json", *run.path.glob("*.xml"), *run.path.glob("junit-*/*.xml"),
             *run.path.glob("semgrep-*.json"), *run.path.glob("codeql-*.sarif"), *run.path.glob("zap.json")]
    for path in paths:
        if not path.exists():
            continue
        def safe_string(value):
            value = redact(value, run.secrets).replace(str(ROOT), "[WORKSPACE]")
            return re.sub(r"[A-Za-z]:[\\/][^\s\"<>]*|/(?:home|Users|mnt|opt|usr|tmp|root)/[^\s\"<>]*", "[LOCAL_PATH]", value)

        def safe_data(value):
            if isinstance(value, str):
                return safe_string(value)
            if isinstance(value, list):
                return [safe_data(item) for item in value]
            if isinstance(value, dict):
                result = {}
                for key, item in value.items():
                    safe_key = safe_string(key)
                    if safe_key in result:
                        raise ValueError("Redaction creates duplicate JSON keys")
                    result[safe_key] = safe_data(item)
                return result
            return value

        raw = path.read_text(encoding="utf-8")
        if path.suffix == ".xml":
            tree = ET.fromstring(raw)
            for node in tree.iter():
                for child in list(node):
                    if child.tag in ("properties", "system-out", "system-err"):
                        node.remove(child)
                node.attrib = {safe_string(key): safe_string(value) for key, value in node.attrib.items()}
                if node.text is not None:
                    node.text = safe_string(node.text)
                if node.tail is not None:
                    node.tail = safe_string(node.tail)
            content = ET.tostring(tree, encoding="unicode")
            ET.fromstring(content)
        else:
            # Redact decoded values, then serialize. Editing serialized JSON can consume
            # the backslash escaping a Windows command's closing quote.
            content = json.dumps(safe_data(json.loads(raw)), ensure_ascii=False, indent=2) + "\n"
            json.loads(content)
        if any(secret in content for secret in run.secrets if len(secret) >= 8):
            raise ValueError("Public artifact contains credential")
        filename = path.name if path.parent == run.path else path.parent.name + "-" + path.name
        (dest / filename).write_text(content, encoding="utf-8")
    return str(dest)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("java", "python", "backend", "frontend", "semgrep", "codeql", "zap", "hygiene", "fixtures", "workflows"))
    args = parser.parse_args()
    run = Run(ROOT / "artifacts/phase6")
    summary = {"stage": args.stage, "status": "FAIL", "run_id": run.id, "environment": sys.platform,
               "python_version": sys.version.split()[0], "implementation_sha256": sha(Path(__file__)),
               "started": __import__('labscan.core', fromlist=['now']).now(), "source_revision": git("rev-parse", "HEAD")}
    exit_code = 1
    try:
        summary["result"] = materialize() if args.stage == "fixtures" else globals()[args.stage if args.stage != "python" else "python_tests"](run)
        summary.update(status="PASS")
        exit_code = 0
    except Exception as error:
        summary["failure"] = redact(str(error), run.secrets)
        summary["failure_diagnostics"] = []
        for record in run.commands:
            if record["execution_status"] != "COMPLETED" or record["label"] == "mysql-failure-logs":
                path = run.path / record["evidence_reference"]
                summary["failure_diagnostics"].append({"label": record["label"],
                    "exit_code": record["exit_code"], "tail": redact(path.read_text(encoding="utf-8")[-8192:], run.secrets)})
    finally:
        from labscan.core import now
        summary.update(ended=now(), exit_code=exit_code, commands=run.commands)
        write_json(run.path / "result.json", summary)
        publish(run)
    print(json.dumps({"status": summary["status"], "stage": args.stage, "run_id": run.id, "exit_code": exit_code}))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
