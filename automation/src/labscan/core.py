"""Immutable evidence, redaction and bounded command execution."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "artifacts/phase4"


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def redact(value, secrets=()):
    if isinstance(value, dict):
        return {k: "[REDACTED]" if re.search(r"password|token|cookie|authorization|secret", k, re.I)
                else redact(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secrets) for v in value]
    if not isinstance(value, str):
        return value
    for secret in sorted(secrets, key=len, reverse=True):
        if secret:
            value = value.replace(secret, "[REDACTED]")
    value = re.sub(r"(?im)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:[^\r\n]*", r"\1: [REDACTED]", value)
    value = re.sub(r"(?i)((?:password|passwd|token|secret|session|api[_-]?key|jsessionid)\s*[=:]\s*)[^\s&;<>\"']+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(https?://)[^/@\s]+:[^/@\s]+@", r"\1[REDACTED]@", value)
    return value


def credentials():
    secrets = [v for k, v in os.environ.items() if re.search(r"password|token|secret|cookie|api_key", k, re.I) and v]
    for name in (".env", ".env.vuln001", ".env.vuln002"):
        path = ROOT / name
        if path.exists():
            for line in path.read_text().splitlines():
                if "=" in line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    if re.search(r"password|token|secret|key", key, re.I) and value:
                        secrets.append(value.strip("\"'"))
    return secrets


def write_json(path, value):
    # Evidence is write-once. State changes use separate timestamped events.
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def load_json(path):
    path = Path(path)
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("JSON exceeds 32 MiB limit")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Non-finite JSON")))


class CommandError(RuntimeError):
    def __init__(self, record):
        self.record = record
        super().__init__(f"{record['label']}: {record['execution_status']}, exit={record['exit_code']}")


class Run:
    def __init__(self, output=OUT, secrets=None):
        self.id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex
        self.path = Path(output) / self.id
        self.path.mkdir(parents=True, exist_ok=False)
        self.secrets = credentials() if secrets is None else secrets
        self.commands = []

    def event(self, value):
        with (self.path / "events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(redact({"timestamp": now(), **value}, self.secrets)) + "\n")

    def command(self, command, label, env=None, cwd=ROOT, timeout=1800, retries=0, accepted=(0,)):
        label = re.sub(r"[^A-Za-z0-9_.-]", "_", label)[:120]
        if not 0 <= retries <= 2 or not 0 < timeout <= 3600:
            raise ValueError("Invalid timeout/retry limit")
        for attempt in range(retries + 1):
            record = {"label": label, "command": redact(list(map(str, command)), self.secrets),
                      "started": now(), "exit_code": None, "execution_status": "FAILED", "attempt": attempt + 1}
            process = None
            interrupted = False
            # Raw stdout/stderr never enter the persistent evidence store before redaction.
            with tempfile.TemporaryFile() as capture:
                try:
                    process = subprocess.Popen(list(map(str, command)), cwd=cwd, env=env,
                                               stdout=capture, stderr=subprocess.STDOUT,
                                               start_new_session=os.name != "nt")
                    record["exit_code"] = process.wait(timeout=timeout)
                    record["execution_status"] = "COMPLETED" if record["exit_code"] in accepted else "FAILED"
                except subprocess.TimeoutExpired:
                    record["execution_status"] = "TIMED_OUT"
                except KeyboardInterrupt:
                    record["execution_status"] = "INTERRUPTED"
                    interrupted = True
                except OSError as error:
                    record["failure"] = str(error)
                finally:
                    if process and process.poll() is None:
                        if os.name == "nt":
                            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True)
                        else:
                            import signal
                            os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    capture.seek(0)
                    content = capture.read().decode("utf-8", errors="replace")
            record["ended"] = now()
            log = self.path / (label + "-" + uuid.uuid4().hex + ".log")
            with log.open("x", encoding="utf-8") as stream:
                stream.write(redact(content, self.secrets))
            record["evidence_reference"] = log.name
            self.commands.append(record)
            self.event({"command": record})
            if label != "target-health" or record["exit_code"] == 0:
                print(f"{label}: {record['execution_status']} exit={record['exit_code']}", flush=True)
            if record["execution_status"] == "COMPLETED":
                return log
            if interrupted:
                raise KeyboardInterrupt
            if attempt < retries:
                time.sleep(min(2 ** attempt, 4))
        raise CommandError(record)

    def manifest(self, paths):
        result = []
        for path in paths:
            path = Path(path).resolve()
            result.append({"path": path.relative_to(self.path.resolve()).as_posix(), "sha256": sha(path)})
        return result


def verify_evidence(directory, manifest):
    if not manifest:
        raise ValueError("Missing evidence manifest")
    directory = Path(directory).resolve()
    for item in manifest:
        path = (directory / item["path"]).resolve()
        if not path.is_relative_to(directory) or not path.is_file() or sha(path) != item["sha256"]:
            raise ValueError("Evidence integrity failure")


def source_identity():
    import sys
    sys.path.insert(0, str(ROOT / 'scripts/public_release'))
    from integrity import source_revision
    revision = source_revision(ROOT)
    paths = subprocess.check_output(["git", "ls-files", "apps", "scanners/semgrep", "scanners/codeql"], cwd=ROOT).decode().splitlines()
    paths += [p.relative_to(ROOT).as_posix() for folder in ("automation", "scanners/zap")
              for p in ROOT.joinpath(folder).rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"]
    digest = hashlib.sha256()
    for name in sorted(set(paths)):
        digest.update(name.encode())
        digest.update(ROOT.joinpath(name).read_bytes().replace(b"\r\n", b"\n"))
    return revision, digest.hexdigest()
