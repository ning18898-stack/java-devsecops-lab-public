"""Local static-analysis Gate. Fixed source roots; no HTTP/ZAP/CI orchestration."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("record", ROOT / "scripts/phase3-command.py")
record = importlib.util.module_from_spec(spec)
spec.loader.exec_module(record)
OUT, run = record.OUT, record.run
SEMGREP = ROOT / ".tools/semgrep/Scripts/semgrep.exe"
CODEQL = ROOT / ".tools/codeql-2.27.2/codeql/codeql.exe"
PACK = ROOT / "scanners/codeql"
JDK = ROOT / ".tools/jdk17/jdk-17.0.20.1+1"


def environment():
    env = dict(os.environ)
    env.update(JAVA_HOME=str(JDK), PATH=str(JDK / "bin") + os.pathsep + env["PATH"],
               PYTHONUTF8="1", SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
    env.pop("SEMGREP_APP_TOKEN", None)
    return env


def protected():
    result = public_integrity()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "protected-files.json").write_text(json.dumps(result), encoding="utf-8")


def semgrep():
    env = environment()
    version = run([str(SEMGREP), "--version"], "semgrep-version", env).read_text().strip()
    if version != "1.180.0":
        raise AssertionError("Unexpected Semgrep version: " + version)
    run([str(SEMGREP), "--validate", "--config", "scanners/semgrep/rules", "--metrics", "off"], "semgrep-validation", env)
    run([str(SEMGREP), "--test", "--config", "scanners/semgrep/rules", "scanners/semgrep/tests", "--metrics", "off"], "semgrep-tests", env)
    result = {}
    for variant in ("vulnerable", "secure"):
        target = f"apps/{variant}-app/src/main/java"
        output = OUT / f"semgrep-{variant}.json"
        run([str(SEMGREP), "scan", "--config", "scanners/semgrep/rules", "--json", "--output", str(output), "--strict",
            "--metrics", "off", "--disable-version-check", "--no-rewrite-rule-ids", target], "semgrep-" + variant, env)
        data = json.loads(output.read_text(encoding="utf-8"))
        expected_files = {p.relative_to(ROOT).as_posix() for p in ROOT.joinpath(target).rglob("*.java")}
        scanned = {p.replace("\\", "/") for p in data["paths"]["scanned"]}
        if data["errors"] or scanned != expected_files:
            raise AssertionError(f"Semgrep error or incomplete scope: {variant}")
        hits = {(r["check_id"], r["path"].replace("\\", "/").split("/")[-1]) for r in data["results"]}
        expected_hits = {("java-sql-provider-concat", "UnsafeSqlProvider.java"),
            ("java-lab-idor-update-scope", "IdorMapper.java")} if variant == "vulnerable" else set()
        if hits != expected_hits or len(data["results"]) != len(expected_hits):
            raise AssertionError(f"Unexpected Semgrep findings: {variant}: {hits}")
        result[variant] = {"files": len(scanned), "findings": len(data["results"]), "status": "PASS"}
    return result


def database(variant, rebuild=False):
    db = OUT / f"db-{variant}"
    source = ROOT / f"apps/{variant}-app"
    digest = hashlib.sha256()
    for path in sorted(source.joinpath("src/main").rglob("*")):
        if path.is_file():
            digest.update(str(path.relative_to(source)).encode())
            digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
    digest.update(source.joinpath("pom.xml").read_bytes().replace(b"\r\n", b"\n"))
    key = {"source_sha256": digest.hexdigest(), "codeql": "2.27.2", "jdk": "17.0.20.1+1",
           "command": "maven clean compile -Dmaven.test.skip=true", "source_root": str(source)}
    stamp = OUT / f"db-{variant}-stamp.json"
    if not rebuild and stamp.exists() and json.loads(stamp.read_text()) == key and db.joinpath("codeql-database.yml").exists():
        print(f"Reuse finalized {variant} database: unchanged source/tool/build fingerprint", flush=True)
        return db
    # CodeQL owns overwrite semantics; no shell-composed recursive filesystem deletion.
    wrapper = ROOT / "apps/vulnerable-app/mvnw.cmd"
    command = f'"{wrapper}" -B -ntp -f "{source / "pom.xml"}" clean compile -Dmaven.test.skip=true'
    run([str(CODEQL), "database", "create", str(db), "--language=java", "--build-mode=manual",
        "--source-root=" + str(source), "--command=" + command, "--overwrite", "--threads=2"],
        "codeql-create-" + variant, environment(), timeout=1800)
    stamp.write_text(json.dumps(key, indent=2))
    return db


def codeql(rebuild=False):
    env = environment()
    version_log = run([str(CODEQL), "version", "--format=json"], "codeql-version", env)
    # Native-access warnings may go to stderr; version stdout is emitted as a file separately below.
    if '"version" : "2.27.2"' not in version_log.read_text():
        raise AssertionError("Unexpected CodeQL CLI version")
    run([str(CODEQL), "pack", "install", str(PACK)], "codeql-pack-install", env)
    run([str(CODEQL), "test", "run", str(PACK / "tests"), "--threads=2", "--ram=4096"], "codeql-tests", env)
    result = {}
    for variant in ("vulnerable", "secure"):
        db = database(variant, rebuild)
        run([str(CODEQL), "database", "analyze", str(db), str(PACK / "lab.qls"),
            "--format=sarif-latest", "--output=" + str(OUT / f"codeql-{variant}.sarif"),
            "--sarif-add-snippets", "--threads=2", "--ram=4096"], "codeql-analyze-" + variant, env)
        sarif = json.loads(OUT.joinpath(f"codeql-{variant}.sarif").read_text())
        hits = sarif["runs"][0]["results"]
        expected = {"java/lab-mybatis-provider-sqli", "java/lab-idor-update-owner", "java/lab-idor-service-owner"} if variant == "vulnerable" else set()
        if {hit["ruleId"] for hit in hits} != expected or len(hits) != len(expected):
            raise AssertionError(f"Unexpected CodeQL findings: {variant}")
        if variant == "vulnerable":
            locations = {"java/lab-mybatis-provider-sqli": ("lab/vuln001/UnsafeSqlProvider.java", 10),
                         "java/lab-idor-update-owner": ("lab/vuln002/IdorMapper.java", 10),
                         "java/lab-idor-service-owner": ("lab/vuln002/IdorService.java", 15)}
            for hit in hits:
                physical = hit["locations"][0]["physicalLocation"]
                suffix, line = locations[hit["ruleId"]]
                if not physical["artifactLocation"]["uri"].endswith(suffix) or physical["region"]["startLine"] != line:
                    raise AssertionError("Unexpected CodeQL alert location: " + hit["ruleId"])
            sql = next(hit for hit in hits if hit["ruleId"] == "java/lab-mybatis-provider-sqli")
            if not sql.get("codeFlows"):
                raise AssertionError("SQLi has no path evidence")
            path = sql["codeFlows"][0]["threadFlows"][0]["locations"]
            path_files = {loc["location"]["physicalLocation"]["artifactLocation"]["uri"].split("/")[-1] for loc in path}
            if path_files != {"LabController.java", "LabService.java", "LabDatabase.java", "UnsafeSqlProvider.java"}:
                raise AssertionError("SQLi path omitted expected propagation components")
        run([str(CODEQL), "query", "run", str(PACK / "diagnostics/ExtractedFiles.ql"),
            "--database=" + str(db), "--output=" + str(OUT / f"files-{variant}.bqrs")], "codeql-files-" + variant, env)
        decoded = OUT / f"files-{variant}.json"
        run([str(CODEQL), "bqrs", "decode", str(OUT / f"files-{variant}.bqrs"), "--format=json",
            "--output=" + str(decoded)], "codeql-files-decode-" + variant, env)
        extracted = {row[0].replace("\\", "/") for row in json.loads(decoded.read_text())["#select"]["tuples"]}
        expected_files = {p.relative_to(ROOT / f"apps/{variant}-app").as_posix()
                          for p in ROOT.joinpath(f"apps/{variant}-app/src/main/java").rglob("*.java")}
        if extracted != expected_files:
            raise AssertionError(f"CodeQL extraction incomplete: {expected_files - extracted}; extra: {extracted - expected_files}")
        result[variant] = {"files": len(extracted), "findings": len(hits), "status": "PASS"}
    db = OUT / "db-vulnerable"
    run([str(CODEQL), "query", "run", str(PACK / "diagnostics/ProviderEdges.ql"),
        "--database=" + str(db), "--output=" + str(OUT / "provider-edges.bqrs")], "codeql-model-edges", env)
    run([str(CODEQL), "bqrs", "decode", str(OUT / "provider-edges.bqrs"), "--format=json",
        "--output=" + str(OUT / "provider-edges.json")], "codeql-model-edges-decode", env)
    run([str(CODEQL), "query", "run", str(PACK / "diagnostics/SqlWithoutBridge.ql"),
        "--database=" + str(db), "--output=" + str(OUT / "without-bridge.bqrs"),
        "--threads=2", "--ram=4096"], "codeql-without-bridge", env)
    run([str(CODEQL), "bqrs", "decode", str(OUT / "without-bridge.bqrs"), "--format=json",
        "--output=" + str(OUT / "without-bridge.json")], "codeql-without-bridge-decode", env)
    no_bridge = json.loads(OUT.joinpath("without-bridge.json").read_text())["#select"]["tuples"]
    if no_bridge:
        raise AssertionError("Framework baseline changed; reassess custom model necessity")
    result["without_bridge_findings"] = len(no_bridge)
    return result


def builds():
    # Reuse sealed credential injection and isolated MySQL setup only for existing tests.
    sys.path.insert(0, str(ROOT / "labs/VULN-002-IDOR"))
    import runtime
    run([sys.executable, "labs/VULN-002-IDOR/manage.py", "up"], "mysql-test-setup", environment())
    result = {}
    for variant, expected in (("vulnerable", 81), ("secure", 41)):
        env = runtime.environment()
        for name in ("VULN001_TEST_DB_URL", "VULN001_TEST_DB_USERNAME", "VULN001_TEST_DB_PASSWORD"):
            env.pop(name, None)
        run(["cmd.exe", "/d", "/c", str(ROOT / "apps/vulnerable-app/mvnw.cmd"), "-B", "-ntp", "-f",
            f"apps/{variant}-app/pom.xml", "clean", "package"], "build-" + variant, env)
        totals = dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)
        dest = OUT / f"junit-{variant}"
        dest.mkdir(exist_ok=True)
        for path in ROOT.joinpath(f"apps/{variant}-app/target/surefire-reports").glob("TEST-*.xml"):
            suite = ET.parse(path).getroot()
            properties = {item.attrib["name"]: item.attrib["value"] for item in suite.find("properties")}
            if not properties["java.version"].startswith("17.") or properties["spring.profiles.active"] != "test":
                raise AssertionError("Unexpected JUnit runtime/profile: " + variant)
            for name in totals:
                totals[name] += int(suite.attrib[name])
            shutil.copy2(path, dest / path.name)
        if totals != {"tests": expected, "failures": 0, "errors": 0, "skipped": 0}:
            raise AssertionError("Unexpected existing regression counts: " + variant)
        result[variant] = totals
    return result


def hygiene():
    result = public_integrity()
    (OUT / "hygiene.json").write_text(json.dumps(result), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", choices=["semgrep", "codeql", "builds", "all"], default="all")
    parser.add_argument("--rebuild-databases", action="store_true")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    summary = {"started": datetime.now(timezone.utc).isoformat(), "stage": args.stage,
               "status": "FAIL", "PHASE3_READY": False}
    try:
        protected()
        run(["git", "write-tree"], "public-source-tree")
        run([str(JDK / "bin/java.exe"), "-version"], "java-version", environment())
        run([sys.executable, "--version"], "python-version")
        run([sys.executable, "-m", "unittest", "discover", "-s", "scripts", "-p", "test_phase3.py"], "runner-tests", environment())
        if args.stage in ("semgrep", "all"):
            summary["semgrep"] = semgrep()
        if args.stage in ("codeql", "all"):
            summary["codeql"] = codeql(args.rebuild_databases)
        if args.stage in ("builds", "all"):
            summary["builds"] = builds()
        protected()
        hygiene()
        run(["git", "diff", "--check"], "git-diff-check")
        summary.update(status="PASS", PHASE3_READY=args.stage == "all")
    except Exception as error:
        summary["failure"] = str(error)
        raise
    finally:
        summary["ended"] = datetime.now(timezone.utc).isoformat()
        OUT.joinpath(f"result-{args.stage}.json").write_text(json.dumps(summary, indent=2) + "\n")
        with OUT.joinpath("stage-history.jsonl").open("a", encoding="utf-8") as output:
            output.write(json.dumps(summary) + "\n")


def public_integrity():
    sys.path.insert(0, str(ROOT / 'scripts/public_release'))
    from integrity import verify
    return verify(ROOT)

if __name__ == "__main__":
    main()

