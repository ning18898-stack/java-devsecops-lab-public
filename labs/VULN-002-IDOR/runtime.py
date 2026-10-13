"""Build/run helpers restricted to this workspace and fixed loopback APIs."""
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
from datetime import datetime, timezone
import urllib.error
import urllib.parse
import urllib.request
import db

JAVA_HOME = db.ROOT / ".tools/jdk17/jdk-17.0.20.1+1"
JAVA = JAVA_HOME / "bin" / ("java.exe" if os.name == "nt" else "java")
BASES = {"vulnerable": "http://127.0.0.1:8080", "secure": "http://127.0.0.1:8081"}
PREFIX = "/api/labs/vuln002"


def environment():
    env = dict(os.environ, **db.credentials())
    path = db.ROOT / ".env.vuln001"
    if path.exists():
        for line in path.read_text().splitlines():
            if line and not line.startswith("#"):
                key, value = line.split("=", 1)
                if key in ("VULN001_DB_PASSWORD", "VULN001_ROOT_PASSWORD"):
                    env[key] = value
    env.update(JAVA_HOME=str(JAVA_HOME), PATH=str(JAVA_HOME / "bin") + os.pathsep + env["PATH"],
        TEST_DB_URL="jdbc:mysql://127.0.0.1:13309/lab_test?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true",
        TEST_DB_USERNAME="v002_regression", TEST_DB_PASSWORD=env["VULN002_MANAGER_PASSWORD"])
    env.update(DB_URL=env["TEST_DB_URL"], DB_USERNAME=env["TEST_DB_USERNAME"], DB_PASSWORD=env["TEST_DB_PASSWORD"])
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(key, None)
    env["NO_PROXY"]="127.0.0.1,localhost"
    if "VULN001_DB_PASSWORD" in env:
        env.update(VULN001_TEST_DB_URL="jdbc:mysql://127.0.0.1:13308/lab_vuln001?allowMultiQueries=false&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true",
            VULN001_TEST_DB_USERNAME="vuln001_reader", VULN001_TEST_DB_PASSWORD=env["VULN001_DB_PASSWORD"])
    # Do not inherit experiment/profile overrides from an interactive terminal.
    for key in ("SPRING_PROFILES_ACTIVE", "SPRING_PROFILES_INCLUDE", "VULN001_ENABLED", "VULN002_ENABLED"):
        env.pop(key, None)
    return env


def command(args, label, env=None, timeout=300):
    log = db.ROOT / "artifacts" / ("vuln002-" + label + ".log")
    log.parent.mkdir(exist_ok=True)
    started = datetime.now(timezone.utc).isoformat()
    exit_code = 1
    try:
        with log.open("w", encoding="utf-8") as output:
            result = subprocess.run(args, cwd=db.ROOT, env=env or environment(), stdout=output,
                stderr=subprocess.STDOUT, timeout=timeout)
        exit_code = result.returncode
    finally:
        with (db.ROOT / "artifacts/vuln002-checks.jsonl").open("a", encoding="utf-8") as metadata:
            metadata.write(json.dumps({"label": label, "command": args, "started": started,
                "ended": datetime.now(timezone.utc).isoformat(), "exit_code": exit_code}) + "\n")
        print(f"{label}: exit code {exit_code}", flush=True)
    if exit_code:
        raise RuntimeError(f"Check failed: {label}")
    return log


def maven(variant, label, *args):
    wrapper = db.ROOT / "apps/vulnerable-app" / ("mvnw.cmd" if os.name == "nt" else "mvnw")
    prefix = ["cmd.exe", "/d", "/c"] if os.name == "nt" else ["sh"]
    env = environment()
    if "-Pmysql" not in args:
        for key in ("VULN001_TEST_DB_URL", "VULN001_TEST_DB_USERNAME", "VULN001_TEST_DB_PASSWORD"):
            env.pop(key, None)
    return command([*prefix, str(wrapper), "-B", "-ntp", "-f", f"apps/{variant}-app/pom.xml", *args], label, env)


def password_hash(password):
    cache = Path.home() / ".m2/repository"
    jars = [cache / "org/springframework/security/spring-security-crypto/7.1.1/spring-security-crypto-7.1.1.jar",
        cache / "commons-logging/commons-logging/1.3.6/commons-logging-1.3.6.jar"]
    result = subprocess.run([str(JAVA), "--class-path", os.pathsep.join(map(str,jars)), str(db.LAB / "PasswordHash.java")],
        input=password + "\n", capture_output=True, text=True, encoding="utf-8", timeout=20)
    if result.returncode or not result.stdout.strip().startswith("$2a$12$"):
        raise RuntimeError("Local Java BCrypt fixture generation failed")
    return result.stdout.strip()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


class Client:
    def __init__(self, variant, jar=None):
        if variant not in BASES:
            raise ValueError("Fixed local variant required")
        self.variant = variant
        self.cookies = jar if jar is not None else http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(self.cookies), NoRedirect())
        self.token = None

    def request(self, method, path, expected, body=None, form=False, csrf=True):
        if not path.startswith("/api/") or ".." in path or "#" in path or "\r" in path or "\n" in path:
            raise ValueError("Only local API paths permitted")
        headers = {}
        if csrf and self.token:
            headers["X-CSRF-TOKEN"] = self.token
        payload = None
        if body is not None:
            payload = (urllib.parse.urlencode(body) if form else json.dumps(body)).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
        request = urllib.request.Request(BASES[self.variant] + path, data=payload, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data, status = response.read(), response.code
        if status != expected:
            raise AssertionError(f"{self.variant} {method} {path}: status {status}, expected {expected}")
        return json.loads(data) if data else None

    def csrf(self):
        self.token = self.request("GET", PREFIX + "/auth/csrf", 200)["token"]

    def login(self, name, password):
        self.csrf()
        self.request("POST", PREFIX + "/auth/login", 200, {"username":name,"password":password}, form=True)
        self.csrf()


class Servers:
    def __init__(self, mode="vuln002", label="runtime"):
        self.processes = []
        self.files = []
        self.mode, self.label = mode, label
    def __enter__(self):
        try:
            import socket
            for port in (8080, 8081):
                with socket.socket() as probe:
                    try: probe.bind(("127.0.0.1",port))
                    except OSError: raise RuntimeError("Required local port already in use")
            for variant in BASES:
                env = environment()
                profiles=[]
                if "vuln001" in self.mode:
                    profiles.append("vuln001-local"); env["VULN001_ENABLED"]="true"
                if "vuln002" in self.mode:
                    profiles.append("vuln002-local"); env["VULN002_ENABLED"]="true"
                if profiles: env["SPRING_PROFILES_ACTIVE"]=",".join(profiles)
                output=(db.ROOT/"artifacts"/f"vuln002-{self.label}-{variant}-jar.log").open("w",encoding="utf-8")
                self.files.append(output)
                process=subprocess.Popen([str(JAVA),"-jar",f"apps/{variant}-app/target/{variant}-app-0.1.0-SNAPSHOT.jar"],
                    cwd=db.ROOT,env=env,stdout=output,stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0)
                self.processes.append(process)
            for variant,process in zip(BASES,self.processes):
                opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
                for attempt in range(60):
                    if process.poll() is not None: raise RuntimeError(f"{variant} JAR exited before startup")
                    try:
                        with opener.open(BASES[variant]+"/actuator/health",timeout=2) as response:
                            if response.code==200 and json.loads(response.read())["status"]=="UP": break
                    except (urllib.error.URLError, TimeoutError): time.sleep(0.5)
                else: raise RuntimeError("JAR health timeout")
            return self
        except Exception:
            self.__exit__(None,None,None); raise
    def __exit__(self,*args):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=15)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
        for output in self.files: output.close()
