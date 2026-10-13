"""Strict tool adapters and versioned observations; counts are not vulnerability counts."""
import hashlib
import json
from datetime import datetime
import re
from pathlib import Path
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit
from .core import now, redact

SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "informational",
            "error": "high", "warning": "medium", "note": "informational",
            "0": "informational", "1": "low", "2": "medium", "3": "high"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def array(data, key):
    require(isinstance(data, dict) and key in data and isinstance(data[key], list), "Missing/invalid array: " + key)
    return data[key]


def location(path, line, variant):
    require(isinstance(path, str) and bool(path), "Missing source path")
    path = unquote(path).replace("\\", "/")
    require(not path.startswith(("/", "file:")) and ":" not in path and ".." not in PurePosixPath(path).parts,
            "Unsafe source path")
    if not path.startswith("apps/"):
        path = f"apps/{variant}-app/" + path
    require(path.startswith(f"apps/{variant}-app/src/main/java/"), "Source outside scanned application")
    require(isinstance(line, int) and not isinstance(line, bool) and line > 0, "Invalid source line")
    return {"path": path, "line": line}


def finding(tool, rule, title, severity, confidence, loc, url, reference, revision, run_id, reasons=None):
    require(isinstance(rule, str) and bool(rule) and isinstance(title, str) and bool(title), "Missing rule/title")
    stable = {"tool": tool, "rule_id": rule, "source_location": loc, "target_url": url}
    fp = hashlib.sha256(json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"schema_version": "1.0", "run_id": run_id, "source_revision": revision,
            "tool": tool, "rule_id": rule, "title": redact(title), "severity": severity,
            "confidence": confidence, "source_location": loc, "target_url": url,
            "evidence_reference": [reference], "finding_status": "unreviewed",
            "execution_status": "COMPLETED", "timestamp": now(), "fingerprint": fp,
            "null_reasons": reasons or {}, "occurrences": 1, "correlation": "new"}


def parse_semgrep(data, reference, revision, run_id, variant):
    rows = array(data, "results")
    require(array(data, "errors") == [], "Semgrep reported errors")
    findings = []
    for row in rows:
        extra = row["extra"]
        severity = SEVERITY.get(extra.get("severity"))
        confidence = extra.get("metadata", {}).get("confidence")
        if confidence not in ("LOW", "MEDIUM", "HIGH"):
            confidence = None
        findings.append(finding("semgrep", row["check_id"], extra["message"], severity,
            confidence.lower() if confidence else None, location(row["path"], row["start"]["line"], variant),
            None, reference, revision, run_id,
            {**({"severity": "Tool severity unavailable/unknown"} if severity is None else {}),
             **({"confidence": "Rule metadata does not specify confidence"} if confidence is None else {}),
             "target_url": "Static source analysis"}))
    return findings


def parse_codeql(data, reference, revision, run_id, variant):
    require(data.get("version") == "2.1.0", "Unsupported SARIF version")
    findings = []
    for run in array(data, "runs"):
        for invocation in run.get("invocations", []):
            require(invocation.get("executionSuccessful") is True, "CodeQL execution failed")
        rules = {r["id"]: r for r in run["tool"]["driver"].get("rules", [])}
        for row in array(run, "results"):
            props = rules.get(row["ruleId"], {}).get("properties", {})
            severity = SEVERITY.get(row.get("level", props.get("problem.severity")))
            confidence = props.get("precision")
            if confidence not in ("low", "medium", "high", "very-high"):
                confidence = None
            loc = None
            reasons = {"target_url": "Static source analysis"}
            if row.get("locations"):
                physical = row["locations"][0]["physicalLocation"]
                loc = location(physical["artifactLocation"]["uri"], physical["region"]["startLine"], variant)
            else:
                reasons["source_location"] = "SARIF result has no physical location"
            if severity is None:
                reasons["severity"] = "SARIF severity unavailable/unknown"
            if confidence is None:
                reasons["confidence"] = "SARIF precision metadata unavailable"
            findings.append(finding("codeql", row["ruleId"], row["message"]["text"], severity,
                confidence, loc, None, reference, revision, run_id, reasons))
    return findings


def parse_zap(data, reference, revision, run_id, host=None):
    findings = []
    for site in array(data, "site"):
        for alert in array(site, "alerts"):
            instances = array(alert, "instances")
            require(instances, "ZAP alert has no instances")
            risk = str(alert.get("riskcode"))
            conf = {"0": "false-positive", "1": "low", "2": "medium", "3": "high", "4": "confirmed"}.get(str(alert.get("confidence")))
            for instance in instances:
                url = instance["uri"]
                if host:
                    from .boundary import check_url
                    check_url(url, host)
                parsed = urlsplit(url)
                require(parsed.scheme == "http" and not parsed.query and not parsed.fragment and not parsed.username,
                        "Unexpected ZAP observation URL")
                # Stable logical target identity; ephemeral container IP is in raw evidence.
                logical = "http://vulnerable-baseline:8080" + parsed.path
                reasons = {"source_location": "HTTP passive analysis"}
                if risk not in SEVERITY:
                    reasons["severity"] = "Unknown ZAP risk code"
                if conf is None:
                    reasons["confidence"] = "Unknown/missing ZAP confidence"
                findings.append(finding("zap", str(alert["pluginid"]), alert.get("name", alert.get("alert")),
                    SEVERITY.get(risk), conf, None, logical, reference, revision, run_id, reasons))
    return findings


def deduplicate(findings):
    grouped = {}
    for item in findings:
        fp = item["fingerprint"]
        if fp not in grouped:
            grouped[fp] = item
        else:
            grouped[fp]["occurrences"] += item["occurrences"]
            grouped[fp]["evidence_reference"] = sorted(set(grouped[fp]["evidence_reference"] + item["evidence_reference"]))
    return sorted(grouped.values(), key=lambda item: item["fingerprint"])


def correlate(findings, previous):
    old = {f["fingerprint"] for f in previous}
    for item in findings:
        item["correlation"] = "previously-observed" if item["fingerprint"] in old else "new"
    return findings


def validate_report(report):
    validate_schema(report, json.loads((Path(__file__).resolve().parents[2] / "report.schema.json").read_text()))
    require(report.get("schema_version") == "1.0", "Unknown report schema")
    require(report.get("execution_status") in ("COMPLETED", "FAILED", "PARTIAL", "NOT_EXECUTED", "INTERRUPTED"), "Invalid run status")
    require(isinstance(report.get("run_id"), str) and isinstance(report.get("source_revision"), str), "Missing run/source")
    steps = array(report, "steps")
    require(len(steps) == 3 and {s["tool"] for s in steps} == {"semgrep", "codeql", "zap"}, "Invalid steps")
    for step in steps:
        status = step["execution_status"]
        require(status in ("COMPLETED", "FAILED", "TIMED_OUT", "INTERRUPTED", "NOT_EXECUTED", "TARGET_UNREACHABLE"), "Invalid step status")
        require((status == "COMPLETED" and isinstance(step["finding_count"], int) and step["finding_count"] >= 0)
                or (status != "COMPLETED" and step["finding_count"] is None), "Failure/not-executed cannot mean zero findings")
    required = {"schema_version", "run_id", "source_revision", "tool", "rule_id", "title", "severity", "confidence",
                "source_location", "target_url", "evidence_reference", "finding_status", "execution_status", "timestamp", "fingerprint", "null_reasons"}
    for item in array(report, "findings"):
        require(required <= item.keys(), "Missing finding fields")
        require(item["run_id"] == report["run_id"] and item["source_revision"] == report["source_revision"], "Mixed provenance")
        require(item["severity"] in (None, "critical", "high", "medium", "low", "informational"), "Invalid severity")
        for key in ("severity", "confidence", "source_location", "target_url"):
            require(item[key] is not None or bool(item["null_reasons"].get(key)), "Unexplained null field")
        require(bool(item["evidence_reference"]), "Missing evidence")
    return report


def validate_schema(value, schema):
    """Validate the documented v1 schema subset, with no runtime framework dependency."""
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        checks = {"object": isinstance(value, dict), "array": isinstance(value, list), "string": isinstance(value, str),
                  "integer": isinstance(value, int) and not isinstance(value, bool), "null": value is None}
        require(any(checks.get(t, False) for t in types), "Schema type mismatch")
    if "enum" in schema:
        require(value in schema["enum"], "Schema enum mismatch")
    if "const" in schema:
        require(value == schema["const"], "Schema constant mismatch")
    if isinstance(value, dict):
        require(set(schema.get("required", [])) <= value.keys(), "Schema required field missing")
        for key, child in schema.get("properties", {}).items():
            if key in value:
                validate_schema(value[key], child)
    if isinstance(value, list):
        require(len(value) >= schema.get("minItems", 0) and len(value) <= schema.get("maxItems", float("inf")), "Schema array size")
        for child in value:
            if "items" in schema:
                validate_schema(child, schema["items"])
    if isinstance(value, str):
        require(len(value) >= schema.get("minLength", 0), "Schema string length")
        if "pattern" in schema:
            require(re.search(schema["pattern"], value) is not None, "Schema string pattern")
        if schema.get("format") == "date-time":
            require(datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None, "Timestamp missing timezone")
    if isinstance(value, int) and "minimum" in schema:
        require(value >= schema["minimum"], "Schema minimum")
    for condition in schema.get("allOf", []):
        try:
            validate_schema(value, condition["if"])
            matches = True
        except ValueError:
            matches = False
        validate_schema(value, condition.get("then" if matches else "else", {}))
