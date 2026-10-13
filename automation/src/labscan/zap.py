"""Disposable local app, scope gateway and official passive ZAP Automation Framework."""
import json
import os
from pathlib import Path
import secrets
import shutil
import time
from .boundary import LABEL, PATHS, TARGET, check_url, validate_container, validate_network
from .core import ROOT, CommandError, load_json, sha, write_json


class TargetUnreachable(RuntimeError):
    pass


def plan(address):
    base = f"http://{address}:8080"
    # JSON is valid YAML 1.2, but explicit YAML keeps ZAP/SnakeYAML compatibility.
    include = "^http://" + address.replace(".", "\\.") + ":8080/(actuator/health|login|api/articles|api/users|api/csrf)$"
    lines = ["env:", "  contexts:", "    - name: local-lab", "      urls:", "        - " + base,
             "      includePaths:", "        - '" + include + "'", "      excludePaths:",
             "        - '.*(/logout|/api/labs/|/register).*'", "  parameters:",
             "    failOnError: true", "    failOnWarning: true", "    progressToStdout: true", "jobs:",
             "  - type: passiveScan-config", "    parameters:", "      scanOnlyInScope: true",
             "      maxAlertsPerRule: 20", "      maxBodySizeInBytesToScan: 1048576",
             "  - type: requestor", "    requests:"]
    for path in PATHS:
        lines.extend(["      - url: " + base + path, "        method: GET"])
    lines.extend(["  - type: passiveScan-wait", "    parameters:", "      maxDuration: 1",
                  "  - type: report", "    parameters:", "      template: traditional-json",
                  "      reportDir: /zap/wrk", "      reportFile: zap.json", "      displayReport: false"])
    return "\n".join(lines) + "\n"


class Sandbox:
    def __init__(self, run, lock):
        self.run = run
        self.lock = lock
        short = run.id[-16:]
        self.scan = "p4-scan-" + short
        self.back = "p4-back-" + short
        self.app = "p4-app-" + short
        self.guard = "p4-guard-" + short
        self.scanner = "p4-zap-" + short
        self.created_containers = []
        self.created_networks = []
        self.images = {}
        self.address = None

    def docker(self, args, label, **kwargs):
        return self.run.command(["docker", *args], label, timeout=kwargs.pop("timeout", 120), **kwargs)

    def inspect(self, kind, name):
        path = self.docker([kind, "inspect", name], "inspect-" + name)
        return json.loads(path.read_text())[0]

    def start(self):
        config = load_json(ROOT / "scanners/zap/plans/passive.json")
        if config != {"mode": "passive-baseline", "target_id": TARGET, "protocol": "http", "port": 8080,
                      "paths": list(PATHS), "excluded_paths": ["/logout", "/api/labs/", "/register"],
                      "methods": ["GET"], "spider": False, "active_scan": False, "follow_redirects": False,
                      "timeout_seconds": 300, "max_requests": 5, "max_response_bytes": 1048576,
                      "scan_memory": "2g", "scan_cpus": "2"}:
            raise ValueError("Unapproved dynamic scan plan")
        for key in ("zap", "java", "python"):
            data = self.inspect("image", self.lock[key])
            if self.lock[key] not in data["RepoDigests"]:
                raise ValueError("Image digest missing")
            self.images[key] = data["Id"]
        # Build test-profile runtime from sealed app; no source modifications.
        env = dict(os.environ)
        jdk = ROOT / ".tools/jdk17/jdk-17.0.20.1+1"
        env.update(JAVA_HOME=str(jdk), PATH=str(jdk / "bin") + os.pathsep + env["PATH"])
        cp = self.run.path / "classpath.txt"
        self.run.command(["cmd.exe", "/d", "/c", str(ROOT / "apps/vulnerable-app/mvnw.cmd"), "-B", "-ntp", "-f",
                          "apps/vulnerable-app/pom.xml", "test-compile", "dependency:build-classpath", "-Dmaven.test.skip=false",
                          "-DincludeScope=test", "-Dmdep.outputFile=" + str(cp)], "app-runtime-build", env)
        runtime = self.run.path / "runtime"
        runtime.mkdir()
        for kind in ("classes", "test-classes"):
            shutil.copytree(ROOT / "apps/vulnerable-app/target" / kind, runtime / kind)
        jars = runtime / "lib"
        jars.mkdir()
        for dependency in cp.read_text().strip().split(os.pathsep):
            path = Path(dependency)
            if path.suffix != ".jar" or not path.is_file():
                raise ValueError("Invalid runtime dependency")
            if (jars / path.name).exists():
                raise ValueError("Duplicate dependency name")
            shutil.copy2(path, jars / path.name)
        write_json(self.run.path / "runtime-manifest.json", {p.relative_to(runtime).as_posix(): sha(p)
                   for p in runtime.rglob("*") if p.is_file()})
        for network in (self.scan, self.back):
            self.docker(["network", "create", "--internal", "--label", LABEL + "=" + self.run.id, network], "network-create")
            self.created_networks.append(network)
        common = ["--detach", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=256",
                  "--memory=1g", "--cpus=1", "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m", "--label", LABEL + "=" + self.run.id]
        password = secrets.token_urlsafe(24)
        self.run.secrets.append(password)
        env["P4_H2_PASSWORD"] = password
        self.docker(["run", *common, "--name", self.app, "--network", self.back, "--network-alias", "application",
                     "--mount", f"type=bind,source={runtime.resolve()},target=/runtime,readonly",
                     "-e", "P4_H2_PASSWORD", self.lock["java"], "java", "-Xmx512m", "-cp", "/runtime/classes:/runtime/test-classes:/runtime/lib/*",
                     "com.example.devsecopslab.LabApplication", "--spring.profiles.active=test", "--server.address=0.0.0.0",
                     "--server.port=8080", "--spring.datasource.username=p4_synthetic", "--spring.datasource.password=${P4_H2_PASSWORD}"],
                    "app-start", env=env)
        self.created_containers.append(self.app)
        back = self.inspect("network", self.back)
        back_subnet = validate_network(back, self.back, self.run.id, [self.app])
        app = self.inspect("container", self.app)
        app_ip = validate_container(app, self.app, self.run.id, self.images["java"], {self.back: back_subnet},
                                   [(str(runtime.resolve()), "/runtime", False)])[self.back]
        # Gateway is the only member of both internal networks. No mounted Docker socket.
        self.docker(["run", *common, "--name", self.guard, "--network", self.scan,
                     "--mount", f"type=bind,source={ROOT / 'automation'},target=/code/automation,readonly",
                     "--mount", f"type=bind,source={ROOT / 'scanners/zap'},target=/code/scanners/zap,readonly",
                     "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "APP_ADDRESS=" + app_ip, "-e", "APP_SUBNET=" + back_subnet,
                     self.lock["python"], "python", "/code/scanners/zap/guard.py"], "guard-start")
        self.created_containers.append(self.guard)
        self.docker(["network", "connect", self.back, self.guard], "guard-connect")
        # SCAN_ADDRESS is discovered after allocation, then passed via exec; restart guard using the same container.
        guard = self.inspect("container", self.guard)
        self.address = guard["NetworkSettings"]["Networks"][self.scan]["IPAddress"]
        # Initial command requires SCAN_ADDRESS only on incoming requests; persist in a file and re-read at request time.
        self.docker(["exec", self.guard, "python", "-c", "from pathlib import Path; Path('/tmp/scan-address').write_text('" + self.address + "')"], "guard-address")
        for attempt in range(45):
            log = self.docker(["exec", self.guard, "python", "-c",
                "import sys; sys.path.insert(0,'/code/scanners/zap'); from guard import exchange; import os,json; "
                "s,h,b=exchange('/actuator/health','application',os.environ['APP_ADDRESS'],os.environ['APP_SUBNET']); "
                "assert s==200 and json.loads(b).get('status')=='UP'; print('identity-health-UP')"],
                "target-health", accepted=(0, 1), timeout=15)
            if "identity-health-UP" in log.read_text():
                break
            time.sleep(1)
        else:
            raise TargetUnreachable("Application health unavailable")
        return self

    def verify(self, scanner=False):
        scan = self.inspect("network", self.scan)
        back = self.inspect("network", self.back)
        scan_subnet = validate_network(scan, self.scan, self.run.id, [self.guard] + ([self.scanner] if scanner else []))
        back_subnet = validate_network(back, self.back, self.run.id, [self.guard, self.app])
        app = self.inspect("container", self.app)
        validate_container(app, self.app, self.run.id, self.images["java"], {self.back: back_subnet},
                           [(str((self.run.path / "runtime").resolve()), "/runtime", False)])
        expected_runtime = load_json(self.run.path / "runtime-manifest.json")
        actual_runtime = {p.relative_to(self.run.path / "runtime").as_posix(): sha(p)
                          for p in (self.run.path / "runtime").rglob("*") if p.is_file()}
        if expected_runtime != actual_runtime:
            raise ValueError("Application binary identity changed")
        command = app["Config"]["Cmd"]
        if ("com.example.devsecopslab.LabApplication" not in command or "--spring.profiles.active=test" not in command or
                "--server.port=8080" not in command or app["Config"].get("Entrypoint") not in (None, ["/__cacert_entrypoint.sh"])):
            raise ValueError("Application command/profile identity changed")
        guard = self.inspect("container", self.guard)
        ips = validate_container(guard, self.guard, self.run.id, self.images["python"], {self.scan: scan_subnet, self.back: back_subnet},
                                 [(str(ROOT / "automation"), "/code/automation", False), (str(ROOT / "scanners/zap"), "/code/scanners/zap", False)])
        if ips[self.scan] != self.address:
            raise ValueError("Scan endpoint changed")
        check_url(f"http://{self.address}:8080/actuator/health", self.address)
        write_json(self.run.path / ("boundary-" + ("scan" if scanner else "pre") + ".json"),
                   {"status": "PASS", "target_id": TARGET, "scan_address": self.address, "scan_subnet": scan_subnet,
                    "back_subnet": back_subnet, "images": self.images, "application_mount_verified": True})

    def scan_zap(self):
        self.verify()
        workspace = self.run.path / "zap-work"
        workspace.mkdir()
        (workspace / "plan.yaml").write_text(plan(self.address), encoding="utf-8")
        # Start an idle container, validate network membership before executing ZAP.
        self.docker(["run", "--detach", "--name", self.scanner, "--network", self.scan, "--label", LABEL + "=" + self.run.id,
                     "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=512", "--memory=2g", "--cpus=2",
                     "--tmpfs", "/tmp:rw,size=256m", "--tmpfs", "/home/zap:rw,size=256m,uid=1000,gid=1000",
                     "--mount", f"type=bind,source={workspace.resolve()},target=/zap/wrk",
                     "-e", "JAVA_OPTS=-Xmx1024m", self.lock["zap"], "sleep", "600"], "zap-create")
        self.created_containers.append(self.scanner)
        self.verify(scanner=True)
        scanner = self.inspect("container", self.scanner)
        scan_subnet = self.inspect("network", self.scan)["IPAM"]["Config"][0]["Subnet"]
        validate_container(scanner, self.scanner, self.run.id, self.images["zap"], {self.scan: scan_subnet},
                           [(str(workspace.resolve()), "/zap/wrk", True)])
        self.docker(["exec", self.scanner, "zap.sh", "-cmd", "-autorun", "/zap/wrk/plan.yaml",
                     "-config", "network.connection.timeoutInSecs=5", "-config", "autoupdate.checkOnStart=false"], "zap-scan", timeout=300)
        tool_exit = self.run.commands[-1]["exit_code"]
        state = self.inspect("container", self.scanner)
        if tool_exit != 0 or state["State"].get("OOMKilled"):
            raise RuntimeError("ZAP process failed")
        report = workspace / "zap.json"
        if not report.exists():
            raise RuntimeError("ZAP did not create JSON report")
        log = self.docker(["logs", self.guard], "guard-audit")
        audit = [json.loads(line) for line in log.read_text().splitlines() if line.startswith("{")]
        if len(audit) != len(PATHS) or {a.get("path") for a in audit} != set(PATHS) or any(a.get("blocked") for a in audit):
            raise ValueError("ZAP request budget/scope/redirect audit failed")
        write_json(self.run.path / "zap-execution.json", {"status": "COMPLETED", "tool_exit_code": tool_exit,
                    "request_count": len(audit), "paths": list(PATHS), "active_scan": False, "spider": False})
        return report, self.address

    def close(self):
        failures = []
        for container in reversed(self.created_containers):
            try:
                self.docker(["logs", container], "cleanup-logs")
                self.docker(["rm", "--force", container], "cleanup-container")
            except Exception as error:
                failures.append(str(error))
        for network in reversed(self.created_networks):
            try:
                self.docker(["network", "rm", network], "cleanup-network")
            except Exception as error:
                failures.append(str(error))
        write_json(self.run.path / "cleanup.json", {"status": "FAILED" if failures else "COMPLETED", "failures": failures})
        if failures:
            raise RuntimeError("Sandbox cleanup failed")
