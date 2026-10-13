from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import sqlite3
import pytest
from fastapi.testclient import TestClient
from app.main import create_app
from app.safety import safe_path, sanitize
from conftest import REAL_ID, RESUME_ID, fixture_report


def first(client):
    fid = client.get("/api/findings").json()["items"][0]["id"]
    return client.get(f"/api/findings/{fid}").json()


def change(client, item, status, **kwargs):
    return client.post(f"/api/findings/{item['id']}/status", json={"status": status, "version": item["version"], "note": "测试：有依据的人工研判", **kwargs})


def test_real_import_and_zero_zap(imported):
    run = imported.get("/api/runs/" + REAL_ID).json()
    assert run["status"] == "COMPLETED"
    assert {s["tool"]: s["finding_count"] for s in run["steps"]} == {"semgrep": 2, "codeql": 3, "zap": 0}
    assert all(s["execution_status"] == "COMPLETED" for s in run["steps"])
    assert run["independent_vulnerability_count"] is None
    summary = imported.get("/api/summary").json()
    assert summary["observations"] == 5 and summary["managed_findings"] == 5
    assert summary["independent_vulnerability_count"] is None
    assert len(run["finding_ids"]) == 5


def test_idempotent_import_preserves_history(imported):
    item = first(imported)
    change(imported, item, "confirmed")
    result = imported.post("/api/imports", json={"run_id": REAL_ID}).json()
    assert result["imported"] is False
    item = imported.get(f"/api/findings/{item['id']}").json()
    assert item["status"] == "confirmed" and len(item["history"]) == 2
    assert imported.get("/api/summary").json()["observations"] == 5


def test_cross_run_same_fingerprint(imported):
    assert imported.post("/api/imports", json={"run_id": RESUME_ID}).status_code == 200
    summary = imported.get("/api/summary").json()
    assert summary["managed_findings"] == 5 and summary["observations"] == 10
    item = first(imported)
    assert {o["run_id"] for o in item["observations"]} == {REAL_ID, RESUME_ID}
    assert len(item["history"]) == 1


def test_source_and_evidence_snapshot(imported):
    item = first(imported)
    obs = item["observations"][0]
    assert obs["source_location"]["line"] > 0
    assert obs["source_snippet"]
    evidence = obs["evidence"][0]
    response = imported.get(f"/api/evidence/{evidence['id']}")
    assert response.status_code == 200
    assert response.json()["sha256"] == evidence["sha256"]
    assert response.headers["x-content-type-options"] == "nosniff"


def test_filters_sort_pagination(imported):
    assert imported.get("/api/findings?tool=codeql").json()["total"] == 3
    assert imported.get("/api/findings?severity=high").json()["total"] == 2
    page1 = imported.get("/api/findings?page_size=2&sort=severity&order=desc").json()
    page2 = imported.get("/api/findings?page_size=2&page=2&sort=severity&order=desc").json()
    assert page1["total"] == 5 and len(page1["items"]) == 2
    assert page1["items"][0]["severity"] == "high"
    assert not {i["id"] for i in page1["items"]} & {i["id"] for i in page2["items"]}
    assert imported.get("/api/findings?query=nonexistent").json()["total"] == 0


@pytest.mark.parametrize("url", ["/api/findings?page=0", "/api/findings?page_size=101", "/api/findings?sort=DROP", "/api/findings?tool=evil", "/api/findings?status=unknown", "/api/runs?page=-1", "/api/evidence/not-a-number"])
def test_bad_parameters(client, url):
    response = client.get(url)
    assert response.status_code == 422 and response.json()["error"]["request_id"]


def test_persistence_reopen(imported, settings):
    item = change(imported, first(imported), "confirmed").json()
    with TestClient(create_app(settings), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 2000)) as restarted:
        persisted = restarted.get(f"/api/findings/{item['id']}").json()
        assert persisted["status"] == "confirmed" and persisted["history"] == item["history"]


def test_legal_lifecycle_and_historical_close_rejection(imported):
    item = first(imported)
    assert change(imported, item, "closed").status_code == 409
    item = change(imported, item, "confirmed").json()
    assert change(imported, {**item, "version": 1}, "fixing").status_code == 409
    item = change(imported, item, "fixing").json()
    assert change(imported, item, "pending_verification").status_code == 409
    item = imported.post(f"/api/findings/{item['id']}/repairs", json={"reference": "unit-test-declaration", "note": "仅单元测试声明，不能冒充真实修复"}).json()
    item = change(imported, item, "pending_verification").json()
    body = {"run_id": REAL_ID, "repair_id": item["repairs"][0]["id"], "evidence_ids": [item["observations"][0]["evidence"][0]["id"]], "conclusion": "remediated", "scope": "历史运行不能证明本次修复", "note": "测试拒绝旧证据"}
    assert imported.post(f"/api/findings/{item['id']}/verifications", json=body).status_code == 409
    body["conclusion"] = "inconclusive"
    item = imported.post(f"/api/findings/{item['id']}/verifications", json=body).json()
    assert item["status"] == "pending_verification"
    assert change(imported, item, "closed", verification_id=item["verifications"][0]["id"]).status_code == 409
    assert len(item["history"]) == 6


@pytest.mark.parametrize("status", ["false_positive", "accepted_risk"])
def test_independent_dispositions(imported, status):
    item = change(imported, first(imported), status).json()
    assert item["status"] == status
    assert item["history"][-1]["note"] and item["history"][-1]["timestamp"]


def test_manual_association_preserves_original_and_future_tracking(imported):
    rows = imported.get("/api/findings").json()["items"]
    source, target = rows[:2]
    assert imported.post(f"/api/findings/{source['id']}/associations", json={"target_id": source["id"], "version": 1, "note": "测试拒绝自身"}).status_code == 409
    response = imported.post(f"/api/findings/{source['id']}/associations", json={"target_id": target["id"], "version": 1, "note": "仅测试人工关联流程，不宣称这两项同源"})
    assert response.status_code == 200
    assert len(response.json()["observations"]) == 2
    archived = imported.get(f"/api/findings/{source['id']}").json()
    assert archived["merged_into"] == target["id"] and len(archived["history"]) == 2
    assert change(imported, archived, "confirmed").status_code == 409
    imported.post("/api/imports", json={"run_id": RESUME_ID})
    assert imported.get("/api/summary").json()["managed_findings"] == 4
    assert len(imported.get(f"/api/findings/{target['id']}").json()["observations"]) == 4


def test_empty_database_and_not_found(client):
    assert client.get("/api/summary").json()["runs"] == 0
    assert client.get("/api/findings").json()["items"] == []
    for url in ("/api/findings/999", "/api/runs/unknown", "/api/evidence/999", "/wrong"):
        response = client.get(url)
        assert response.status_code == 404 and "error" in response.json()


@pytest.mark.parametrize("client_address,host,origin", [("192.168.1.2", "127.0.0.1:8000", None), ("127.0.0.1", "evil.example", None), ("127.0.0.1", "127.0.0.1:8000", "https://evil.example"), ("127.0.0.1", "127.0.0.1:8000", "null")])
def test_network_boundary(settings, client_address, host, origin):
    with TestClient(create_app(settings), base_url="http://" + host, client=(client_address, 1000)) as client:
        headers = {"origin": origin} if origin else {}
        assert client.get("/api/session", headers=headers).status_code == 403


def test_missing_token_and_error_redaction(client):
    client.headers.pop("x-dashboard-token")
    assert client.post("/api/imports", json={"run_id": REAL_ID}).status_code == 403
    client.headers["x-dashboard-token"] = client.get("/api/session").json()["write_token"]
    response = client.post("/api/imports", json={"run_id": "../.env", "password": "must-not-be-echoed"})
    assert response.status_code == 422 and "must-not-be-echoed" not in response.text
    assert client.post("/api/imports", content="bad-json", headers={"content-type": "application/json"}).status_code == 422
    assert client.post("/api/imports", content="text").status_code == 415
    assert client.post("/api/imports", content=b"x" * (1024 * 1024 + 1), headers={"content-type": "application/json"}).status_code == 413


def test_internal_exception_envelope(client, monkeypatch):
    monkeypatch.setattr(client.app.state.database, "connect", lambda: (_ for _ in ()).throw(RuntimeError("secret internal path")))
    response = client.get("/api/health")
    assert response.status_code == 500 and "secret internal path" not in response.text


def test_immutability(imported, settings):
    with imported.app.state.database.connect() as db:
        for table in ("scan_runs", "observations", "evidence", "finding_history", "repairs", "verifications"):
            if table in ("repairs", "verifications"):
                continue
            with pytest.raises(sqlite3.IntegrityError):
                db.execute(f"DELETE FROM {table}")


@pytest.mark.parametrize("name", ["../secret", "/etc/passwd", "C:/Users/secret", "%2e%2e/secret", "a\\..\\b", ".env", "a/../../b"])
def test_path_boundary(tmp_path, name):
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        safe_path(tmp_path, name)


def test_symlink_boundary(tmp_path):
    from fastapi import HTTPException
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    import subprocess
    # Windows junction doesn't require developer-mode symbolic-link privileges.
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(base / "escape"), str(outside)], capture_output=True)
    assert result.returncode == 0
    with pytest.raises(HTTPException):
        safe_path(base, "escape/secret")


def test_secret_and_xss_text(imported):
    item = first(imported)
    note = '<img src=x onerror=alert(1)> password=never-show-this'
    response = imported.post(f"/api/findings/{item['id']}/notes", json={"note": note})
    assert response.status_code == 200 and "never-show-this" not in response.text
    assert response.json()["history"][-1]["note"].startswith("<img")
    assert "never-show-this" not in sanitize({"password": "never-show-this"})["password"]
    assert "quoted secret" not in sanitize("password='quoted secret'")


def test_missing_evidence_is_explicit(fixture_client):
    client, root = fixture_client
    fixture_report(root)
    response = client.post("/api/imports", json={"run_id": "fixture"})
    assert response.status_code == 200 and response.json()["warnings"]
    obs = first(client)["observations"][0]
    assert obs["evidence"][0]["availability"] == "missing"
    assert client.get(f"/api/evidence/{obs['evidence'][0]['id']}").status_code == 404


@pytest.mark.parametrize("mutation", [lambda d: d.update(schema_version="2"), lambda d: d["findings"][0].update(fingerprint="0" * 64), lambda d: d["findings"][0]["source_location"].update(path=".env"), lambda d: d["steps"][0].update(finding_count=500), lambda d: d["evidence_manifest"][0].update(path="../secret"), lambda d: d["findings"][0].update(evidence_reference=["unregistered.json"])])
def test_invalid_reports_are_atomic(fixture_client, mutation):
    client, root = fixture_client
    fixture_report(root, mutate=mutation)
    assert client.post("/api/imports", json={"run_id": "fixture"}).status_code == 422
    assert client.get("/api/summary").json()["runs"] == 0


def test_broken_json_and_hash_mismatch(fixture_client):
    client, root = fixture_client
    data, directory = fixture_report(root)
    file = data["evidence_manifest"][0]["path"]
    path = directory / file
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("corrupted")
    assert client.post("/api/imports", json={"run_id": "fixture"}).status_code == 409
    (directory / "report.json").write_text("{")
    assert client.post("/api/imports", json={"run_id": "fixture"}).status_code == 422


def test_conflicting_run_is_rejected(fixture_client):
    client, root = fixture_client
    data, directory = fixture_report(root)
    assert client.post("/api/imports", json={"run_id": "fixture"}).status_code == 200
    data["timestamp"] = "2030-01-01T00:00:00Z"
    (directory / "report.json").write_text(json.dumps(data))
    assert client.post("/api/imports", json={"run_id": "fixture"}).status_code == 409


@pytest.mark.parametrize("run_status,step_status", [("FAILED", "FAILED"), ("NOT_EXECUTED", "NOT_EXECUTED"), ("INTERRUPTED", "INTERRUPTED"), ("PARTIAL", "TIMED_OUT")])
def test_failed_and_unexecuted_runs(fixture_client, run_status, step_status):
    client, root = fixture_client
    def mutation(data):
        data["execution_status"] = run_status
        data["findings"] = []
        for step in data["steps"]:
            step.update(execution_status=step_status, finding_count=None, execution_mode="not-executed")
    fixture_report(root, mutate=mutation)
    assert client.post("/api/imports", json={"run_id": "fixture"}).status_code == 200
    run = client.get("/api/runs/fixture").json()
    assert run["status"] == run_status and all(s["finding_count"] is None for s in run["steps"])


def test_operational_evidence_not_exposed(imported):
    run = imported.get("/api/runs/" + REAL_ID).json()
    log = next(e for e in run["evidence"] if e["path"].endswith(".log"))
    assert imported.get(f"/api/evidence/{log['id']}").status_code == 403
    assert "command" not in run and "raw_report" not in run


def test_verified_close_contract_with_synthetic_evidence(fixture_client):
    """Positive lifecycle contract only; does not assert any real issue is remediated."""
    client, root = fixture_client
    fixture_report(root)
    client.post("/api/imports", json={"run_id": "fixture"})
    item = change(client, first(client), "confirmed").json()
    item = change(client, item, "fixing").json()
    item = client.post(f"/api/findings/{item['id']}/repairs", json={"reference": "synthetic-contract", "note": "合成单元测试声明"}).json()
    item = change(client, item, "pending_verification").json()
    def mutation(data):
        data["timestamp"] = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()
        data["findings"] = []
        for step in data["steps"]:
            step["finding_count"] = 0
        content = b'{"synthetic_unit_test": true}'
        data["evidence_manifest"] = [{"path": "zap.json", "sha256": sha256(content).hexdigest()}]
        for step in data["steps"]:
            step["evidence"] = ["zap.json"]
    data, directory = fixture_report(root, "synthetic-retest", mutation)
    (directory / "zap.json").write_bytes(b'{"synthetic_unit_test": true}')
    client.post("/api/imports", json={"run_id": "synthetic-retest"})
    eid = client.get("/api/runs/synthetic-retest").json()["evidence"][0]["id"]
    body = {"run_id": "synthetic-retest", "repair_id": item["repairs"][0]["id"], "evidence_ids": [eid], "conclusion": "remediated", "scope": "只验证 API 数据契约的合成测试输入", "note": "不代表真实修复"}
    body["evidence_ids"] = [999999]
    assert client.post(f"/api/findings/{item['id']}/verifications", json=body).status_code == 422
    body["evidence_ids"] = [eid]
    item = client.post(f"/api/findings/{item['id']}/verifications", json=body).json()
    item = change(client, item, "closed", verification_id=item["verifications"][0]["id"]).json()
    assert item["status"] == "closed"
    item = change(client, item, "confirmed").json()
    assert item["status"] == "confirmed"


def test_concurrent_import_is_idempotent(client):
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: client.post("/api/imports", json={"run_id": REAL_ID}), range(3)))
    assert all(r.status_code == 200 for r in results)
    assert sum(r.json()["imported"] for r in results) == 1
    assert client.get("/api/summary").json()["managed_findings"] == 5


def test_concurrent_status_cannot_overwrite(imported):
    from concurrent.futures import ThreadPoolExecutor
    item = first(imported)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda status: change(imported, item, status), ["confirmed", "false_positive"]))
    assert sorted(r.status_code for r in results) == [200, 409]
    assert len(imported.get(f"/api/findings/{item['id']}").json()["history"]) == 2
