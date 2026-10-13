"""Read-only Phase 4 import, verified manifests and atomic/idempotent persistence."""
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
from jsonschema import Draft202012Validator, FormatChecker
from fastapi import HTTPException
from .config import ROOT
from .safety import error, safe_path, sanitize
from labscan.core import now
from labscan.results import validate_report

MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 48 * 1024 * 1024
SCHEMA = json.loads((ROOT / "automation/report.schema.json").read_text())


def limited_read(path):
    if not path.is_file():
        return None
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        error(413, "扫描输入超过大小限制")
    return data


def identity(item):
    return json.dumps({k: item[k] for k in ("tool", "rule_id", "source_location", "target_url")},
                      sort_keys=True, separators=(",", ":"))


def source_snippet(item):
    loc = item["source_location"]
    if loc is None:
        return None
    try:
        top = Path(subprocess.check_output(['git', 'rev-parse', '--show-toplevel'],
                                          cwd=ROOT, stderr=subprocess.DEVNULL, timeout=5).decode().strip()).resolve()
        if top != ROOT.resolve():
            return None
        raw = subprocess.check_output(["git", "cat-file", "blob", f"{item['source_revision']}:{loc['path']}"],
                                      cwd=ROOT, stderr=subprocess.DEVNULL, timeout=5)
        lines = raw.decode("utf-8").splitlines()
        start = max(0, loc["line"] - 4)
        return sanitize("\n".join(f"{i + 1}: {lines[i]}" for i in range(start, min(len(lines), start + 9))))
    except (subprocess.SubprocessError, UnicodeError):
        return None


def import_run(database, settings, run_id):
    run_dir = safe_path(settings.imports, run_id)
    raw = limited_read(safe_path(run_dir, "report.json"))
    if raw is None:
        error(404, "扫描运行记录不存在")
    digest = sha256(raw).hexdigest()
    try:
        report = json.loads(raw)
        Draft202012Validator(SCHEMA, format_checker=FormatChecker()).validate(report)
        validate_report(report)
        if report["run_id"] != run_id or len(report["findings"]) > 10000 or len(report["evidence_manifest"]) > 2000:
            raise ValueError()
        seen = set()
        for item in report["findings"]:
            if item["fingerprint"] in seen or sha256(identity(item).encode()).hexdigest() != item["fingerprint"]:
                raise ValueError()
            seen.add(item["fingerprint"])
            loc = item["source_location"]
            if loc:
                path = loc["path"]
                safe_path(ROOT, path)
                if not re.fullmatch(r"apps/(vulnerable|secure)-app/src/main/java/[A-Za-z0-9_/]+\.java", path):
                    raise ValueError()
        counts = Counter(f["tool"] for f in report["findings"])
        for step in report["steps"]:
            if step["execution_status"] == "COMPLETED":
                if step["finding_count"] != counts[step["tool"]]:
                    raise ValueError()
            elif counts[step["tool"]]:
                raise ValueError()
        complete = all(s["execution_status"] == "COMPLETED" for s in report["steps"])
        if (report["execution_status"] == "COMPLETED") != complete:
            raise ValueError()
    except HTTPException:
        raise
    except Exception:
        error(422, "扫描 JSON 不符合 Phase 4 数据契约")
    # Validate every reference, even unavailable evidence; no filesystem paths from API clients.
    snapshots = {}
    total = len(raw)
    for entry in report["evidence_manifest"]:
        path = safe_path(run_dir, entry["path"])
        if entry["path"] in snapshots:
            error(422, "证据引用重复")
        data = limited_read(path)
        if data is not None and sha256(data).hexdigest() != entry["sha256"]:
            error(409, "证据摘要不匹配，拒绝导入")
        total += len(data or b"")
        if total > MAX_TOTAL:
            error(413, "证据总量超过限制")
        snapshots[entry["path"]] = (entry["sha256"], data)
    references = [p for f in report["findings"] for p in f["evidence_reference"]]
    references += [p for step in report["steps"] for p in step["evidence"]]
    if any(p not in snapshots for p in references):
        error(422, "证据引用未登记在 manifest")
    with database.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        existing = db.execute("SELECT report_sha256 FROM scan_runs WHERE id=?", (run_id,)).fetchone()
        if existing:
            if existing[0] != digest:
                error(409, "同一运行标识的原始记录发生改变")
            return {"run_id": run_id, "imported": False, "warnings": []}
        timestamp = now()
        steps = [{k: s[k] for k in ("tool", "execution_status", "finding_count", "execution_mode", "exit_codes", "evidence")}
                 for s in report["steps"]]
        versions = {k: report["tool_versions"].get(k) for k in ("python", "jdk", "semgrep", "codeql", "zap")}
        db.execute("INSERT INTO scan_runs VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (run_id, digest, raw, report["source_revision"], report["source_fingerprint"],
                    report["timestamp"], report["execution_status"], json.dumps(steps), json.dumps(versions), timestamp))
        evidence_ids = {}
        for path, (hash_value, data) in snapshots.items():
            cursor = db.execute("INSERT INTO evidence(run_id,path,sha256,content,availability) VALUES (?,?,?,?,?)",
                                (run_id, path, hash_value, data, "available" if data is not None else "missing"))
            evidence_ids[path] = cursor.lastrowid
        for item in report["findings"]:
            key = db.execute("SELECT * FROM finding_keys WHERE fingerprint=?", (item["fingerprint"],)).fetchone()
            stable = identity(item)
            if key and key["identity"] != stable:
                error(409, "指纹身份冲突")
            if not key:
                cursor = db.execute("INSERT INTO findings(title,severity,created_at,updated_at) VALUES (?,?,?,?)",
                                    (sanitize(item["title"]), item["severity"], timestamp, timestamp))
                fid = cursor.lastrowid
                db.execute("INSERT INTO finding_keys VALUES (?,?,?,?,?)",
                           (item["fingerprint"], fid, item["tool"], item["rule_id"], stable))
                db.execute("INSERT INTO finding_history(finding_id,action,to_status,note,timestamp) VALUES (?,?,?,?,?)",
                           (fid, "import", "unreviewed", "工具报告导入；独立漏洞尚未确认", timestamp))
            cursor = db.execute("INSERT INTO observations(run_id,fingerprint,tool,rule_id,raw_json,source_snippet) VALUES (?,?,?,?,?,?)",
                                (run_id, item["fingerprint"], item["tool"], item["rule_id"],
                                 json.dumps(item, ensure_ascii=False), source_snippet(item)))
            for path in set(item["evidence_reference"]):
                db.execute("INSERT INTO observation_evidence VALUES (?,?)", (cursor.lastrowid, evidence_ids[path]))
    return {"run_id": run_id, "imported": True,
            "warnings": ["缺失证据：" + p for p, (_, data) in snapshots.items() if data is None]}
