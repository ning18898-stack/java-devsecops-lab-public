import json
from pathlib import Path
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.config import ROOT, Settings
from app.main import create_app

REAL_ID = "release-example-001"
RESUME_ID = "release-example-002"


@pytest.fixture
def settings(tmp_path):
    return Settings(tmp_path / "test.sqlite3", ROOT / "artifacts/phase4")


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings), base_url="http://127.0.0.1:8000", client=("127.0.0.1", 40000)) as client:
        client.headers["x-dashboard-token"] = client.get("/api/session").json()["write_token"]
        yield client


@pytest.fixture
def imported(client):
    response = client.post("/api/imports", json={"run_id": REAL_ID})
    assert response.status_code == 200, response.text
    return client


@pytest.fixture
def fixture_client(tmp_path):
    root = tmp_path / "imports"
    root.mkdir()
    settings = Settings(tmp_path / "fixture.sqlite3", root)
    app = create_app(settings)
    with TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 40000)) as client:
        client.headers["x-dashboard-token"] = client.get("/api/session").json()["write_token"]
        yield client, root


def fixture_report(root, run_id="fixture", mutate=None):
    """Explicit synthetic test input derived from schema; never used in demo/gate data."""
    data = json.loads((ROOT / "artifacts/phase4" / REAL_ID / "report.json").read_text())
    data["run_id"] = run_id
    for finding in data["findings"]:
        finding["run_id"] = run_id
    if mutate:
        mutate(data)
    path = root / run_id
    path.mkdir(exist_ok=True)
    (path / "report.json").write_text(json.dumps(data), encoding="utf-8")
    return data, path
