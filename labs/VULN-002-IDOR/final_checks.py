"""Check scoped changes, protected source, local links, JARs and secret exclusion."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile
import db
import runtime as rt


def git(*args):
    return subprocess.check_output(["git", *args], cwd=db.ROOT)


def main():
    sys.path.insert(0, str(db.ROOT / 'scripts/public_release'))
    from integrity import verify
    result = verify(db.ROOT)
    protected = result['files']
    changed = set(git('ls-files').decode('utf-8').splitlines())
    secret_values = list(db.credentials().values())
    for filename in (".env.vuln001", ".env"):
        path = db.ROOT / filename
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line and not line.startswith("#") and "=" in line:
                    name, value = line.split("=", 1)
                    if name.endswith("PASSWORD") and value:
                        secret_values.append(value)
    # Only changed source/doc files and this experiment's own runtime evidence.
    evidence = [path for path in (db.ROOT / "artifacts").glob("vuln002-*") if path.is_file()]
    evidence += list((db.ROOT / "artifacts").glob("vuln002-*-reports/TEST-*.xml"))
    contents = [(db.ROOT / name).read_text(encoding="utf-8") for name in sorted(changed)]
    contents += [path.read_text(encoding="utf-8", errors="replace") for path in evidence]
    if any(secret in content for content in contents for secret in secret_values):
        raise AssertionError("Credential detected in source or experiment evidence")
    links = 0
    for name in sorted(changed):
        if not name.endswith(".md"):
            continue
        path = db.ROOT / name
        for link in re.findall(r"\[[^\]]*\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
            if "://" in link or link.startswith("#"):
                continue
            target = link.split("#", 1)[0]
            if not (path.parent / target).exists():
                raise AssertionError("Broken local documentation link")
            links += 1
    for name in (".env", ".env.vuln001", ".env.vuln002", ".tools/jdk17/", "artifacts/vuln002-final-checks.log"):
        if subprocess.run(["git", "check-ignore", "-q", "--", name], cwd=db.ROOT).returncode:
            raise AssertionError("Credential or runtime output is not ignored")
    rt.command(["git", "diff", "--check"], "diff-check")
    jars = {}
    for variant in ("vulnerable", "secure"):
        path = db.ROOT / f"apps/{variant}-app/target/{variant}-app-0.1.0-SNAPSHOT.jar"
        with zipfile.ZipFile(path) as jar:
            if any("h2-" in name or "application-test.yml" in name or "application-mysql-test.yml" in name for name in jar.namelist()):
                raise AssertionError("Production JAR contains test runtime")
            classes = [name for name in jar.namelist() if name.startswith("BOOT-INF/classes/com/example/") and name.endswith(".class")]
            if not classes or any(int.from_bytes(jar.read(name)[6:8], "big") != 61 for name in classes):
                raise AssertionError("Application bytecode is not Java 17")
        jars[variant] = hashlib.sha256(path.read_bytes()).hexdigest()
    acceptance = json.loads((db.ROOT / "artifacts/vuln002-acceptance-result.json").read_text(encoding="utf-8"))
    if acceptance["status"] != "PASS" or acceptance["exit_code"] != 0:
        raise AssertionError("Completed acceptance evidence missing")
    result = {"protected_files": len(protected), "changed_files": len(changed), "local_links": links,
        "secret_exclusion": "PASS", "scope": "PASS", "jars_sha256": jars, "exit_code": 0}
    (db.ROOT / "artifacts/vuln002-final-checks.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Final checks FAIL {type(error).__name__}; exit code 1")
        sys.exit(1)
