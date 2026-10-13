"""Reuse sealed Phase 3 runners and own Phase 4 provenance and recovery."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid
from .boundary import TARGET
from .core import ROOT, OUT, CommandError, Run, load_json, now, redact, sha, source_identity, verify_evidence, write_json
from .results import correlate, deduplicate, parse_codeql, parse_semgrep, parse_zap, validate_report
from .zap import Sandbox, TargetUnreachable

TAGS = {}
DOCS = {"PROJECT.md", "TASKS.md", "docs/architecture.md", "docs/validation/phase4-validation.md"}


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def protected(run):
    result = public_integrity()
    write_json(run.path / ("protected-" + str(len(list(run.path.glob("protected-*.json")))) + ".json"), result)
    return result


def phase3(run):
    spec = importlib.util.spec_from_file_location("sealed_phase3", ROOT / "scripts/verify-phase3.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.OUT = run.path
    def recorded(command, label, env=None, **kwargs):
        if list(map(str, command)) == [sys.executable, "labs/VULN-002-IDOR/manage.py", "up"]:
            command = [sys.executable, str(ROOT / "automation/regression_setup.py")]
        return run.command(command, label, env, **kwargs)
    module.run = recorded
    original_database = module.database

    def database(variant, rebuild=False):
        historic = ROOT / "artifacts/phase3"
        stamp = historic / f"db-{variant}-stamp.json"
        db = historic / f"db-{variant}"
        if not rebuild and stamp.exists() and db.joinpath("codeql-database.yml").exists():
            # The sealed implementation validates source/tool/build fingerprint before reuse.
            old = module.OUT
            module.OUT = historic
            try:
                # Prevent overwriting old evidence if stamp no longer matches.
                import hashlib
                source = ROOT / f"apps/{variant}-app"
                digest = hashlib.sha256()
                for path in sorted(source.joinpath("src/main").rglob("*")):
                    if path.is_file():
                        digest.update(str(path.relative_to(source)).encode())
                        digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
                digest.update(source.joinpath("pom.xml").read_bytes().replace(b"\r\n", b"\n"))
                expected = {"source_sha256": digest.hexdigest(), "codeql": "2.27.2", "jdk": "17.0.20.1+1",
                            "command": "maven clean compile -Dmaven.test.skip=true", "source_root": str(source)}
                if load_json(stamp) != expected:
                    raise ValueError("Historical CodeQL database fingerprint differs")
                # Validate all bytes of the finalized database; pin that evidence in this run.
                manifest = {p.relative_to(db).as_posix(): sha(p) for p in db.rglob("*") if p.is_file()}
                write_json(run.path / f"database-reuse-{variant}-{uuid.uuid4().hex}.json", {"origin": str(db.relative_to(ROOT)),
                           "source_tool_build": expected, "files": manifest, "mode": "historical-database-new-analysis"})
                snapshot = old / f"db-{variant}"
                if not snapshot.exists():
                    shutil.copytree(db, snapshot)
                # Analyze a private snapshot; never overwrite historical database query caches.
                return snapshot
            finally:
                module.OUT = old
        return original_database(variant, rebuild)
    module.database = database
    return module


def preflight(run, tools):
    module = phase3(run)
    versions = {"python": sys.version.split()[0]}
    if sys.version.split()[0] != "3.11.9":
        raise ValueError("Validated host runtime requires Python 3.11.9")
    if os.name != "nt":
        raise ValueError("Ubuntu orchestration NOT_TESTED; Windows-only Phase 3 adapter")
    log = run.command([str(module.JDK / "bin/java.exe"), "-version"], "jdk-version", module.environment(), timeout=30)
    if '17.0.20.1' not in log.read_text():
        raise ValueError("Project JDK 17 version mismatch")
    versions["jdk"] = "17.0.20.1+1"
    lock = load_json(ROOT / "scanners/zap/images.lock.json") if "zap" in tools else {}
    if "semgrep" in tools:
        log = run.command([str(module.SEMGREP), "--version"], "semgrep-preflight", module.environment(), timeout=60)
        if log.read_text().strip() != "1.180.0":
            raise ValueError("Semgrep version mismatch")
        versions["semgrep"] = "1.180.0"
        python = ROOT / ".tools/semgrep/Scripts/python.exe"
        freeze = run.command([str(python), "-m", "pip", "freeze"], "semgrep-dependencies", timeout=60).read_text()
        installed = {line.strip().lower() for line in freeze.splitlines() if line.strip()}
        locked = {line.strip().lower() for line in (ROOT / "scanners/semgrep/requirements.lock.txt").read_text().splitlines()
                  if line.strip() and not line.startswith("#")}
        if installed != locked:
            raise ValueError("Semgrep dependency lock differs from installed environment")
        versions["semgrep_dependency_lock"] = sha(ROOT / "scanners/semgrep/requirements.lock.txt")
    if "codeql" in tools:
        log = run.command([str(module.CODEQL), "version", "--format=json"], "codeql-preflight", module.environment(), timeout=60)
        if '"version" : "2.27.2"' not in log.read_text():
            raise ValueError("CodeQL version mismatch")
        versions["codeql"] = "2.27.2"
        if sha(ROOT / ".tools/codeql-win64-2.27.2.zip") != "6c90c8503af7b13827a151fbada959c1e5e4a49dd4ebad5bf0855f8a54404c1b":
            raise ValueError("CodeQL official archive checksum mismatch")
        versions["codeql_pack_lock"] = sha(ROOT / "scanners/codeql/codeql-pack.lock.yml")
    if "zap" in tools:
        log = run.command(["docker", "version", "--format", "{{json .}}"], "docker-preflight", timeout=30)
        docker = json.loads(log.read_text())
        versions["docker"] = docker["Server"]["Version"]
        for name in ("zap", "java", "python"):
            if "@sha256:" not in lock[name] or len(lock[name].split("@sha256:")[1]) != 64:
                raise ValueError("Unpinned image")
            log = run.command(["docker", "image", "inspect", lock[name]], "image-preflight", timeout=30)
            image = json.loads(log.read_text())[0]
            if lock[name] not in image["RepoDigests"]:
                raise ValueError("Image digest mismatch")
        log = run.command(["docker", "run", "--rm", "--network=none", lock["zap"], "zap.sh", "-version"], "zap-version", timeout=90)
        if lock["zap_version"] not in log.read_text():
            raise ValueError("ZAP version mismatch")
        versions["zap"] = lock["zap_version"]
        versions["images"] = lock
    write_json(run.path / "preflight.json", {"status": "PASS", "tool_versions": versions})
    return versions, lock


def parse_outputs(tool, paths, revision, run_id, address=None):
    findings = []
    for path in paths:
        data = load_json(path)
        ref = str(path.name)
        variant = "secure" if "secure" in path.name else "vulnerable"
        if tool == "semgrep":
            findings += parse_semgrep(data, ref, revision, run_id, variant)
        elif tool == "codeql":
            findings += parse_codeql(data, ref, revision, run_id, variant)
        else:
            findings += parse_zap(data, ref, revision, run_id, address)
    return deduplicate(findings)


def sanitized_evidence(path, run):
    data = redact(load_json(path), run.secrets)
    # Preserve tool structure and metadata; sensitive values become explicit placeholders.
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def previous_run(run_id):
    if not run_id or "/" in run_id or "\\" in run_id or run_id in (".", ".."):
        raise ValueError("Invalid historical run ID")
    directory = (OUT / run_id).resolve()
    if directory.parent != OUT.resolve():
        raise ValueError("Invalid historical directory")
    report_path = directory / "report.json"
    if not report_path.exists():
        checkpoints = sorted(directory.glob("checkpoint-*.json"))
        if not checkpoints:
            raise ValueError("No verified completed checkpoint")
        report_path = checkpoints[-1]
    report = validate_report(load_json(report_path))
    if report["run_id"] != run_id:
        raise ValueError("Historical run ID mismatch")
    verify_evidence(directory, report["evidence_manifest"])
    recorded = {f["fingerprint"] for f in report["findings"]}
    verified = set()
    allowed = {item["path"] for item in report["evidence_manifest"]}
    for step in report["steps"]:
        if step["execution_status"] == "COMPLETED":
            if not step["evidence"] or not all(name in allowed for name in step["evidence"]):
                raise ValueError("Missing completed-step evidence")
            rows = parse_outputs(step["tool"], [directory / name for name in step["evidence"]],
                                 report["source_revision"], report["run_id"])
            if len(rows) != step["finding_count"]:
                raise ValueError("Historical observation count mismatch")
            verified.update(f["fingerprint"] for f in rows)
    if verified != recorded:
        raise ValueError("Historical observations do not match verified raw evidence")
    return directory, report


def execute(tools, dry_run=False, target=TARGET, resume=None, correlate_with=None, retries=1):
    run = Run()
    revision, fingerprint = source_identity()
    started = now()
    steps = [{"tool": tool, "execution_status": "NOT_EXECUTED", "finding_count": None, "execution_mode": "not-executed",
              "exit_codes": [], "evidence": []} for tool in ("semgrep", "codeql", "zap")]
    findings = []
    versions = {}
    failure = None
    interrupted = False
    def checkpoint():
        evidence = [p for p in run.path.iterdir() if p.is_file() and p.name != "events.jsonl" and not p.name.startswith("checkpoint-")]
        data = {"schema_version": "1.0", "run_id": run.id, "source_revision": revision, "source_fingerprint": fingerprint,
                "tool_versions": versions, "timestamp": now(), "execution_status": "PARTIAL", "dry_run": False,
                "steps": steps, "findings": deduplicate(copy_findings(findings)), "evidence_manifest": run.manifest(evidence)}
        validate_report(data)
        index = len(list(run.path.glob("checkpoint-*.json"))) + 1
        write_json(run.path / f"checkpoint-{index:03d}.json", redact(data, run.secrets))
    try:
        protected(run)
        if source_identity() != (revision, fingerprint):
            raise ValueError("Source/configuration changed during execution; evidence retained but run invalid")
        if target != TARGET:
            raise ValueError("Unauthorized target; dynamic scan not started")
        versions, lock = preflight(run, tools)
        parent_dir, parent = previous_run(resume) if resume else (None, None)
        if parent and (parent["source_fingerprint"] != fingerprint or parent["source_revision"] != revision or
                       parent["tool_versions"] != versions or parent.get("dry_run")):
            raise ValueError("Resume source/tool/config mismatch or dry-run parent")
        module = phase3(run)
        if not dry_run:
            for step in steps:
                tool = step["tool"]
                if tool not in tools:
                    continue
                previous = next((s for s in parent["steps"] if s["tool"] == tool), None) if parent else None
                # Dynamic scan always validates a fresh target. Static completed results may be reused.
                if tool != "zap" and previous and previous["execution_status"] == "COMPLETED":
                    paths = []
                    for name in previous["evidence"]:
                        source = parent_dir / name
                        dest = run.path / source.name
                        with dest.open("xb") as stream:
                            stream.write(source.read_bytes())
                        paths.append(dest)
                    parsed = parse_outputs(tool, paths, revision, run.id)
                    step.update(execution_status="COMPLETED", execution_mode="historical-reuse", parent_run_id=resume,
                                finding_count=len(parsed), evidence=[p.name for p in paths], exit_codes=previous["exit_codes"])
                    findings += parsed
                    run.event({"step": step})
                    checkpoint()
                    continue
                begin = len(run.commands)
                step["execution_mode"] = "actual-execution"
                for attempt in range(retries + 1):
                    work = run.path / (tool + "-attempt-" + str(attempt + 1))
                    work.mkdir()
                    step["started"] = now()
                    try:
                        if tool in ("semgrep", "codeql"):
                            module.OUT = work
                            # Phase 3 runner writes output paths supplied by its existing detector logic.
                            result = module.semgrep() if tool == "semgrep" else module.codeql()
                            paths = [work / (f"{tool}-{v}.json" if tool == "semgrep" else f"codeql-{v}.sarif")
                                     for v in ("vulnerable", "secure")]
                            address = None
                            step["integration_contract"] = result
                        else:
                            sandbox = Sandbox(run, lock)
                            try:
                                sandbox.start()
                                raw, address = sandbox.scan_zap()
                                paths = [raw]
                            finally:
                                sandbox.close()
                        copied = []
                        for path in paths:
                            sanitized_evidence(path, run)
                        parsed = parse_outputs(tool, paths, revision, run.id, address)
                        for path in paths:
                            dest = run.path / path.name
                            with dest.open("xb") as stream:
                                stream.write(path.read_bytes())
                            copied.append(dest)
                        step.update(execution_status="COMPLETED", finding_count=len(parsed), evidence=[p.name for p in copied])
                        step.pop("failure", None)
                        findings += parsed
                        break
                    except KeyboardInterrupt:
                        step["execution_status"] = "INTERRUPTED"
                        interrupted = True
                        raise
                    except Exception as error:
                        step["execution_status"] = (error.record["execution_status"] if isinstance(error, CommandError)
                            else "TARGET_UNREACHABLE" if isinstance(error, TargetUnreachable) else "FAILED")
                        step["failure"] = redact(str(error), run.secrets)
                        run.event({"step_failure": dict(step), "attempt": attempt + 1})
                        # ZAP has a finite internal lifecycle, no blind retry after identity or audit failure.
                        if tool == "zap" or attempt == retries:
                            break
                    finally:
                        step["ended"] = now()
                        for path in work.glob("*"):
                            if path.is_file() and path.suffix in (".json", ".sarif"):
                                try:
                                    sanitized_evidence(path, run)
                                except (ValueError, KeyError):
                                    path.write_text(redact(path.read_text(encoding="utf-8", errors="replace"), run.secrets), encoding="utf-8")
                step["exit_codes"] = [c["exit_code"] for c in run.commands[begin:]]
                run.event({"step": step})
                checkpoint()
        protected(run)
        if source_identity() != (revision, fingerprint):
            raise ValueError("Source/configuration changed during execution; evidence retained but run invalid")
    except KeyboardInterrupt:
        failure = "Interrupted by operator; completed evidence retained for recovery"
        interrupted = True
    except Exception as error:
        failure = redact(str(error), run.secrets)
        run.event({"failure": failure})
    findings = deduplicate(findings)
    if correlate_with:
        try:
            _, old = previous_run(correlate_with)
            findings = correlate(findings, old["findings"])
        except Exception as error:
            failure = str(error)
    complete = [s for s in steps if s["tool"] in tools and s["execution_status"] == "COMPLETED"]
    status = ("INTERRUPTED" if interrupted else "FAILED" if failure else "NOT_EXECUTED" if dry_run
              else "COMPLETED" if len(complete) == len(tools) else "PARTIAL" if complete else "FAILED")
    evidence = [p for p in run.path.iterdir() if p.is_file() and p.name != "events.jsonl"]
    report = {"schema_version": "1.0", "run_id": run.id, "source_revision": revision, "source_fingerprint": fingerprint,
              "target_id": target, "tool_versions": versions, "started": started, "timestamp": now(), "ended": now(),
              "execution_status": status, "dry_run": dry_run, "failure": failure, "steps": steps,
              "findings": findings, "observation_count": len(findings) if complete else None,
              "count_completeness": "complete" if status == "COMPLETED" else "partial" if complete else "none",
              "independent_vulnerability_count": None,
              "count_reason": "Tool observations may overlap; no cross-tool independence assumption",
              "configuration": {"tools": tools, "target": target, "retries": retries, "resume": resume,
                                "passive_plan": load_json(ROOT / "scanners/zap/plans/passive.json")},
              "evidence_manifest": run.manifest(evidence), "commands": run.commands}
    validate_report(report)
    write_json(run.path / "report.json", redact(report, run.secrets))
    print(f"run_id={run.id} status={status}; " + "; ".join(f"{s['tool']}={s['execution_status']} observations={s['finding_count']}" for s in steps), flush=True)
    return run, report


def copy_findings(findings):
    # Deduplication updates occurrence counters; checkpointing must not mutate live findings.
    import copy
    return copy.deepcopy(findings)

def public_integrity():
    sys.path.insert(0, str(ROOT / 'scripts/public_release'))
    from integrity import verify
    return verify(ROOT)
