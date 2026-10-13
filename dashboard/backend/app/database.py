from contextlib import contextmanager
from pathlib import Path
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY, report_sha256 TEXT NOT NULL, raw_report BLOB NOT NULL,
    source_revision TEXT NOT NULL, source_fingerprint TEXT NOT NULL,
    timestamp TEXT NOT NULL, status TEXT NOT NULL, steps TEXT NOT NULL,
    tool_versions TEXT NOT NULL, imported_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY, title TEXT NOT NULL, severity TEXT,
    status TEXT NOT NULL DEFAULT 'unreviewed', version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    merged_into INTEGER REFERENCES findings(id)
);
CREATE TABLE IF NOT EXISTS finding_keys (
    fingerprint TEXT PRIMARY KEY, finding_id INTEGER NOT NULL REFERENCES findings(id),
    tool TEXT NOT NULL, rule_id TEXT NOT NULL, identity TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES scan_runs(id),
    fingerprint TEXT NOT NULL REFERENCES finding_keys(fingerprint), tool TEXT NOT NULL,
    rule_id TEXT NOT NULL, raw_json TEXT NOT NULL, source_snippet TEXT,
    UNIQUE(run_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES scan_runs(id),
    path TEXT NOT NULL, sha256 TEXT NOT NULL, content BLOB,
    availability TEXT NOT NULL, UNIQUE(run_id, path)
);
CREATE TABLE IF NOT EXISTS observation_evidence (
    observation_id INTEGER NOT NULL REFERENCES observations(id),
    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
    PRIMARY KEY(observation_id, evidence_id)
);
CREATE TABLE IF NOT EXISTS finding_history (
    id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL REFERENCES findings(id),
    action TEXT NOT NULL, from_status TEXT, to_status TEXT,
    note TEXT NOT NULL, timestamp TEXT NOT NULL, actor TEXT NOT NULL DEFAULT 'local-user'
);
CREATE TABLE IF NOT EXISTS repairs (
    id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL REFERENCES findings(id),
    reference TEXT NOT NULL, note TEXT NOT NULL, timestamp TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verifications (
    id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL REFERENCES findings(id),
    repair_id INTEGER NOT NULL REFERENCES repairs(id), run_id TEXT NOT NULL REFERENCES scan_runs(id),
    evidence_ids TEXT NOT NULL, conclusion TEXT NOT NULL,
    scope TEXT NOT NULL, note TEXT NOT NULL, timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS observation_run_idx ON observations(run_id);
CREATE INDEX IF NOT EXISTS finding_status_idx ON findings(status);
CREATE INDEX IF NOT EXISTS history_finding_idx ON finding_history(finding_id);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise RuntimeError("Unsupported database schema")
            db.executescript(SCHEMA)
            # Immutable inputs/history cannot be overwritten even by application mistakes.
            for table in ("scan_runs", "observations", "evidence", "observation_evidence",
                          "finding_history", "repairs", "verifications"):
                for action in ("UPDATE", "DELETE"):
                    db.execute(f"CREATE TRIGGER IF NOT EXISTS immutable_{table}_{action} "
                               f"BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT, 'immutable'); END")
            db.execute("PRAGMA user_version=1")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()
