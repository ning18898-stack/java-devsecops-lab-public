"""Fixed local VULN-002 database tooling. Each call creates an independent connection."""
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "labs/VULN-002-IDOR"
SUFFIXES = ("vulnerable", "secure", "vulnerable_test", "secure_test")
KEYS = tuple("VULN002_" + key + "_PASSWORD" for key in ("ROOT", "APP", "MANAGER", "READER"))


def credentials(create=False):
    path = ROOT / ".env.vuln002"
    values = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if line and not line.startswith("#"):
                key, value = line.split("=", 1)
                if key not in KEYS or key in values:
                    raise ValueError("Invalid credential file")
                values[key] = value
    if create:
        for key in KEYS:
            if not values.get(key):
                values[key] = secrets.token_hex(24)
        temporary = ROOT / ".env.vuln002.generated"
        temporary.write_text("".join(f"{key}={values[key]}\n" for key in KEYS), encoding="utf-8")
        temporary.replace(path)
        if os.name != "nt":
            path.chmod(0o600)
    if set(values) != set(KEYS) or any(not re.fullmatch(r"[a-f0-9]{48}", v) for v in values.values()):
        raise ValueError("Initialize valid local credentials first")
    return values


def compose(*args, timeout=180):
    result = subprocess.run(["docker", "compose", "--env-file", str(ROOT / ".env.vuln002"),
        "-f", str(LAB / "compose.yml"), *args], cwd=ROOT, capture_output=True,
        text=True, encoding="utf-8", timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"VULN-002 Compose failed; exit code {result.returncode}")
    return result.stdout


def sql(suffix, role, statement, expect_failure=False):
    if suffix not in SUFFIXES or role not in ("app", "manager", "reader"):
        raise ValueError("Only dedicated VULN-002 accounts permitted")
    env = dict(os.environ, MYSQL_PWD=credentials()[f"VULN002_{role.upper()}_PASSWORD"])
    cid = compose("ps", "-q", "mysql").strip()
    if not re.fullmatch(r"[a-f0-9]{12,64}", cid):
        raise ValueError("Dedicated container not running")
    result = subprocess.run(["docker", "exec", "-i", "-e", "MYSQL_PWD", cid, "mysql",
        "--protocol=TCP", "-h127.0.0.1", "-u", f"v002_{suffix}_{role}", "--batch", "--raw",
        "--skip-column-names", f"lab_vuln002_{suffix}"], input=statement,
        env=env, text=True, encoding="utf-8", capture_output=True, timeout=20)
    if expect_failure:
        if result.returncode == 0:
            raise AssertionError("Forbidden database operation succeeded")
        if not re.search(r"ERROR (1044|1142|1143) ", result.stderr):
            raise AssertionError("Operation failed for a reason other than access denial")
        return None
    if result.returncode:
        raise RuntimeError(f"Isolated SQL failed; exit code {result.returncode}")
    return result.stdout.strip()


def literal(value):
    return "CONVERT(0x" + value.encode().hex() + " USING utf8mb4)"


def require_run(run):
    if not re.fullmatch(r"[a-f0-9]{32}", run):
        raise ValueError("Invalid run identifier")


def prepare(suffix, run, hashes):
    require_run(run)
    if len(hashes) != 2:
        raise ValueError("Two independent user hashes required")
    names = ["alice_" + run, "bob_" + run]
    for name, hashed in zip(names, hashes):
        sql(suffix, "manager", f"INSERT INTO lab_users(run_id,username,password_hash,role) VALUES({literal(run)},{literal(name)},{literal(hashed)},'USER');")
    ids = [int(sql(suffix, "manager", f"SELECT id FROM lab_users WHERE username={literal(name)};")) for name in names]
    articles = []
    for owner, title in zip(ids, ("Alice target", "Bob control")):
        articles.append(int(sql(suffix, "manager", f"INSERT INTO lab_articles(run_id,user_id,title,content) VALUES({literal(run)},{owner},{literal(title)},'Initial synthetic content'); SELECT LAST_INSERT_ID();")))
    return {"run": run, "names": names, "users": ids, "articles": articles}


def snapshot(suffix):
    result = sql(suffix, "reader", "SELECT JSON_OBJECT('id',id,'run_id',run_id,'owner',user_id,'title',title,'content',content,'created_at',CAST(created_at AS CHAR),'updated_at',CAST(updated_at AS CHAR)) FROM lab_articles ORDER BY id;")
    return [json.loads(line) for line in result.splitlines() if line]


def cleanup(suffix, run):
    require_run(run)
    sql(suffix, "manager", f"START TRANSACTION; DELETE FROM lab_articles WHERE run_id={literal(run)}; DELETE FROM lab_users WHERE run_id={literal(run)}; COMMIT;")


def isolation():
    runs = [uuid.uuid4().hex, uuid.uuid4().hex]
    before = {suffix: snapshot(suffix) for suffix in SUFFIXES}
    try:
        for suffix in SUFFIXES:
            for run in runs:
                generated = prepare(suffix, run, ["unused-stage-a", "unused-stage-a"])
            for other in SUFFIXES:
                if other != suffix:
                    sql(suffix, "app", f"SELECT * FROM lab_vuln002_{other}.lab_articles;", True)
            visible = sql(suffix, "app", "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA ORDER BY SCHEMA_NAME;").splitlines()
            assert set(visible) <= {"information_schema", "performance_schema", f"lab_vuln002_{suffix}"}
            for forbidden, table in (("lab", "articles"), ("lab_test", "articles"), ("lab_vuln001", "lab_articles")):
                sql(suffix, "app", f"SELECT * FROM {forbidden}.{table};", True)
            owner = generated["users"][0]
            sql(suffix, "app", f"INSERT INTO lab_articles(run_id,user_id,title,content) VALUES('x',{owner},'x','x');", True)
            sql(suffix, "app", f"UPDATE lab_articles SET user_id={owner};", True)
            sql(suffix, "reader", "UPDATE lab_articles SET title='x';", True)
            sql(suffix, "manager", "DROP TABLE lab_articles;", True)
            cleanup(suffix, runs[0])
            assert len([row for row in snapshot(suffix) if row['run_id'] == runs[1]]) == 2
            cleanup(suffix, runs[1])
            assert snapshot(suffix) == before[suffix]
    finally:
        for suffix in SUFFIXES:
            for run in runs:
                cleanup(suffix, run)
    print("Stage A isolation PASS: 4 schemas, cross-schema denial, minimum grants, run-scoped cleanup; exit code 0")


if __name__ == "__main__":
    import sys
    try:
        if sys.argv[1:] == ["init"]:
            credentials(True)
            print("Local credential initialization complete; values suppressed; exit code 0")
        elif sys.argv[1:] == ["isolation"]:
            isolation()
        else:
            raise ValueError("Use init or isolation only")
    except Exception as error:
        print(f"FAIL {type(error).__name__}; exit code 1")
        sys.exit(1)


def regression_database():
    """Explicitly approved disposable fifth schema; never touches old containers/volumes."""
    env = dict(os.environ, MYSQL_PWD=credentials()["VULN002_ROOT_PASSWORD"])
    cid = compose("ps", "-q", "mysql").strip()
    schema = (ROOT / "infra/mysql/init/001-schema.sql").read_text()
    password = credentials()["VULN002_MANAGER_PASSWORD"]
    statement = "CREATE DATABASE IF NOT EXISTS lab_test; USE lab_test; " + schema + (
        "CREATE USER IF NOT EXISTS 'v002_regression'@'%' IDENTIFIED BY '" + password + "'; "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON lab_test.* TO 'v002_regression'@'%';")
    result = subprocess.run(["docker", "exec", "-i", "-e", "MYSQL_PWD", cid, "mysql", "-uroot"],
        input=statement, env=env, capture_output=True, text=True, encoding="utf-8", timeout=20)
    if result.returncode:
        raise RuntimeError("Disposable regression schema initialization failed")
    print("Approved disposable lab_test initialized in dedicated VULN-002 container; exit code 0")
