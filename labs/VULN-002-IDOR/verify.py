"""Fixed local IDOR PoC; secure comparison runs as MySQL regression tests."""
import json
import sys
import time
import uuid
import xml.etree.ElementTree as ET
import db
import runtime as rt


def require_unchanged(before, after):
    if before != after:
        raise AssertionError("Refused operation changed independent database snapshot")


def require_changed(before, after, title, content):
    if after["title"] != title or after["content"] != content:
        raise AssertionError("Expected committed update missing")
    for field in ("id", "run_id", "owner", "created_at"):
        if after[field] != before[field]:
            raise AssertionError("Update changed immutable database field")
    if before["updated_at"] == after["updated_at"]:
        raise AssertionError("Committed update timestamp did not change")


def row(run_rows, article_id):
    return next(item for item in run_rows if item["id"] == article_id)


def secure_regression(label):
    started = time.time()
    rt.maven("secure", label, "-Pmysql", "-Dtest=IdorArticleTest", "test")
    report = db.ROOT / "apps/secure-app/target/surefire-reports/TEST-com.example.securelab.vuln002.IdorArticleTest.xml"
    if report.stat().st_mtime < started - 2:
        raise AssertionError("Fresh secure regression evidence missing")
    suite = ET.parse(report).getroot()
    counts = {name: int(suite.attrib[name]) for name in ("tests", "failures", "errors", "skipped")}
    if counts != {"tests": 13, "failures": 0, "errors": 0, "skipped": 0}:
        raise AssertionError("Secure comparison did not execute all article checks")
    properties = {item.attrib["name"]: item.attrib["value"] for item in suite.find("properties")}
    if not properties["java.version"].startswith("17.") or properties["spring.profiles.active"] != "mysql-test":
        raise AssertionError("Secure comparison requires actual JDK 17 and mysql-test")
    return counts


def verify(label="poc"):
    run, guardian = uuid.uuid4().hex, uuid.uuid4().hex
    original = {suffix: db.snapshot(suffix) for suffix in db.SUFFIXES}
    passwords = ["Alice-" + uuid.uuid4().hex, "Bob-" + uuid.uuid4().hex]
    hashes = [rt.password_hash(value) for value in passwords]
    client, alice, anonymous = (rt.Client("vulnerable") for _ in range(3))
    try:
        fixtures = db.prepare("vulnerable", run, hashes)
        db.prepare("vulnerable", guardian, hashes)
        seeded = db.snapshot("vulnerable")
        target, control = fixtures["articles"]
        before = row(seeded, target)
        path = rt.PREFIX + "/articles/" + str(target)
        anonymous.csrf()
        anonymous.request("PUT", path, 401, {"title": "anonymous", "content": "refused"})
        require_unchanged(seeded, db.snapshot("vulnerable"))
        client.login(fixtures["names"][1], passwords[1])
        identity = client.request("GET", rt.PREFIX + "/info", 200)
        if identity != {"labId": "VULN-002", "variant": "vulnerable", "fixtures": "v1"}:
            raise AssertionError("Fixed local lab identity mismatch")
        if client.request("GET", rt.PREFIX + "/auth/me", 200)["id"] != fixtures["users"][1]:
            raise AssertionError("Real Bob authentication missing")
        if client.request("GET", path, 200)["userId"] != fixtures["users"][0]:
            raise AssertionError("Target must belong to Alice")
        client.request("PUT", path, 403, {"title": "no csrf", "content": "refused"}, csrf=False)
        require_unchanged(seeded, db.snapshot("vulnerable"))
        client.request("PUT", path, 400, {"title": "spoof", "content": "refused", "userId": fixtures["users"][0]})
        require_unchanged(seeded, db.snapshot("vulnerable"))
        other_id = next(item["id"] for item in seeded if item["run_id"] == guardian)
        client.request("PUT", rt.PREFIX + "/articles/" + str(other_id), 404,
            {"title": "another run", "content": "refused"})
        require_unchanged(seeded, db.snapshot("vulnerable"))
        client.request("PUT", path, 200, {"title": "Bob committed update", "content": "IDOR synthetic evidence"})
        after = db.snapshot("vulnerable")
        require_changed(before, row(after, target), "Bob committed update", "IDOR synthetic evidence")
        require_unchanged([item for item in seeded if item["id"] != target],
            [item for item in after if item["id"] != target])
        alice.login(fixtures["names"][0], passwords[0])
        alice.request("PUT", path, 200, {"title": "Alice owner update", "content": "Owner operation"})
        require_changed(row(after, target), row(db.snapshot("vulnerable"), target),
            "Alice owner update", "Owner operation")
        counts = secure_regression(label + "-secure-mysql")
        for suffix in ("secure", "vulnerable_test", "secure_test"):
            require_unchanged(original[suffix], db.snapshot(suffix))
        result = {"run": run, "status": "PASS", "vulnerable_cross_user_http": 200,
            "secure_cross_user_test": 403, "secure_tests": counts,
            "independent_database_evidence": True, "target_before": before,
            "target_after_bob": row(after, target), "control_id": control, "exit_code": 0}
    finally:
        for actor in (client, alice):
            if actor.token:
                actor.request("POST", rt.PREFIX + "/auth/logout", 200)
        for identifier in (run, guardian):
            db.cleanup("vulnerable", identifier)
        for suffix in db.SUFFIXES:
            require_unchanged(original[suffix], db.snapshot(suffix))
    (db.ROOT / "artifacts" / ("vuln002-" + label + "-result.json")).write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"VULN-002 {label} PASS: Bob HTTP 200, committed foreign article update; secure MySQL 403 and unchanged row; run {run}; cleanup verified; exit code 0", flush=True)
    return result


if __name__ == "__main__":
    try:
        if len(sys.argv) != 1:
            raise ValueError("No target or payload arguments accepted")
        verify()
    except Exception as error:
        print(f"VULN-002 FAIL {type(error).__name__}; exit code 1", flush=True)
        sys.exit(1)
