"""Verify only this local lab, then run its secure MySQL regression tests."""
import http.cookiejar
import json
import logging
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
BASE = "http://127.0.0.1:8080"
PATH = "/api/labs/vuln001/articles/search"
MYSQL_URL = "jdbc:mysql://127.0.0.1:13308/lab_vuln001?allowMultiQueries=false&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true"
PAYLOAD = "' OR '1'='1"

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None

class Client:
    def __init__(self):
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(self.cookies), NoRedirect())
        self.token = None

    def request(self, method, path, expected, data=None, form=False):
        if not path.startswith("/api/"):
            raise ValueError("Only fixed local API paths are permitted")
        headers = {}
        if self.token:
            headers["X-CSRF-TOKEN"] = self.token
        if data is None:
            payload = None
        elif form:
            payload = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            payload = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(BASE + path, data=payload, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read()
            status = response.code
        if status != expected:
            raise AssertionError(f"Unexpected HTTP status {status}; expected {expected}")
        logging.info("PASS %s %s -> %s", method, path.split("?")[0], status)
        return json.loads(body) if body else None

    def csrf(self):
        self.token = self.request("GET", "/api/auth/csrf", 200)["token"]


def require_ids(rows, expected):
    if [row["id"] for row in rows] != expected:
        raise AssertionError("Unexpected fixture query result")


def secure_regression():
    if os.environ.get("VULN001_TEST_DB_URL") != MYSQL_URL or os.environ.get("VULN001_TEST_DB_USERNAME") != "vuln001_reader":
        raise ValueError("Secure regression requires the fixed local MySQL fixture database")
    if not os.environ.get("VULN001_TEST_DB_PASSWORD"):
        raise ValueError("Secure regression requires an environment password")
    java_home = os.environ.get("JAVA_HOME")
    if not java_home:
        raise ValueError("Set project JDK 17 JAVA_HOME for this process")
    java = Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java")
    version = subprocess.run([str(java), "-version"], capture_output=True, text=True, check=True)
    if 'version "17.' not in version.stderr:
        raise ValueError("PoC regression requires actual Java 17")
    logging.info("%s", version.stderr.strip())
    wrapper = ROOT / "apps/vulnerable-app" / ("mvnw.cmd" if os.name == "nt" else "mvnw")
    arguments = [str(wrapper), "-B", "-ntp", "-f", "apps/secure-app/pom.xml", "-Pmysql", "-Dtest=LabQueryTest", "test"]
    if os.name == "nt":
        if any(character in str(ROOT) for character in '&|<>^()%!\r\n'):
            raise ValueError("Workspace path contains unsupported command-shell characters")
        arguments = ["cmd.exe", "/d", "/c", *arguments]
    else:
        arguments = ["sh", *arguments]
    logging.info("Starting secure variant regression against the same local MySQL fixtures")
    started = time.time()
    result = subprocess.run(arguments, cwd=ROOT, timeout=180, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    (ROOT / "artifacts/vuln001-poc-secure-tests.log").write_text(result.stdout, encoding="utf-8")
    if result.returncode:
        raise RuntimeError(f"Secure regression exit code {result.returncode}; inspect local test log")
    report = ROOT / "apps/secure-app/target/surefire-reports/TEST-com.example.securelab.vuln001.LabQueryTest.xml"
    if not report.exists() or report.stat().st_mtime < started - 2:
        raise AssertionError("Fresh secure regression report is missing")
    suite = ET.parse(report).getroot()
    counts = {name: int(suite.attrib[name]) for name in ["tests", "failures", "errors", "skipped"]}
    if counts != {"tests": 9, "failures": 0, "errors": 0, "skipped": 0}:
        raise AssertionError("Secure regression did not complete all expected checks")
    properties = {item.attrib["name"]: item.attrib["value"] for item in suite.find("properties")}
    if not properties["java.version"].startswith("17.") or properties["spring.profiles.active"] != "mysql-test":
        raise AssertionError("Secure test report does not use Java 17 / mysql-test")
    logging.info("PASS secure MySQL regression: %s", counts)
    return counts


def main():
    if len(sys.argv) != 1:
        raise ValueError("This PoC accepts no target or payload arguments")
    (ROOT / "artifacts").mkdir(exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", handlers=[
        logging.StreamHandler(), logging.FileHandler(ROOT / "artifacts/vuln001-poc.log", encoding="utf-8")])
    run = uuid.uuid4().hex[:12]
    logging.info("Starting VULN-001 local verification; run %s", run)
    (ROOT / "artifacts/vuln001-poc-result.json").write_text(json.dumps({"run": run, "status": "RUNNING"}))
    anonymous = Client()
    anonymous.request("GET", PATH + "?q=Alpha", 401)
    client = Client()
    client.csrf()
    name = "vuln001_" + run
    password = secrets.token_urlsafe(24)
    client.request("POST", "/api/auth/register", 201,
                   {"username": name, "email": name + "@example.test", "password": password})
    client.request("POST", "/api/auth/login", 200, {"username": name, "password": password}, form=True)
    client.csrf()
    try:
        identity = client.request("GET", "/api/labs/vuln001/info", 200)
        if identity != {"labId": "VULN-001", "variant": "vulnerable", "fixtures": "v1", "mode": "local-readonly"}:
            raise AssertionError("Local lab identity mismatch")
        for query, expected in [("Alpha public article", [1]), ("Synthetic draft article", []),
                                (PAYLOAD, [1, 2, 3]), ("' OR '1'='2", [])]:
            rows = client.request("GET", PATH + "?q=" + urllib.parse.quote(query, safe=""), 200)
            require_ids(rows, expected)
            logging.info("PASS fixture query returned IDs %s", expected)
        baseline = client.request("GET", "/api/articles/search?q=" + urllib.parse.quote(PAYLOAD, safe=""), 200)
        if any(PAYLOAD not in row["title"] and PAYLOAD not in row["content"] for row in baseline):
            raise AssertionError("Original baseline search stopped treating the payload literally")
        counts = secure_regression()
        summary = {"run": run, "vulnerable_normal_ids": [1], "vulnerable_injected_ids": [1, 2, 3],
                   "secure_injected_ids": [], "secure_tests": counts, "exit_code": 0}
    finally:
        client.request("POST", "/api/auth/logout", 200)
    (ROOT / "artifacts/vuln001-poc-result.json").write_text(json.dumps(summary, indent=2) + "\n")
    logging.info("VULN-001 complete; synthetic login user retained; exit code 0")

if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        (ROOT / "artifacts").mkdir(exist_ok=True)
        (ROOT / "artifacts/vuln001-poc-result.json").write_text(json.dumps({"status": "FAIL", "error_type": type(error).__name__, "exit_code": 1}))
        logging.error("VULN-001 failed: %s; exit code 1", type(error).__name__)
        sys.exit(1)
