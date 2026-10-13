"""Deterministic unit tests: synthetic tool fixtures and mocked network/process failures."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from labscan.boundary import (LABEL, PATHS, check_address, check_url, reject_redirect, resolve_exact,
                              validate_container, validate_network)
from labscan.core import (CommandError, ROOT, Run, load_json, redact, sha, verify_evidence, write_json)
from labscan.results import (correlate, deduplicate, finding, parse_codeql, parse_semgrep, parse_zap, validate_report)
from labscan.workflow import execute, previous_run, phase3
from labscan.zap import plan

spec = importlib.util.spec_from_file_location("scope_guard", ROOT / "scanners/zap/guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def semgrep():
    return {"results": [{"check_id": "unit-sqli", "path": "apps/vulnerable-app/src/main/java/A.java",
                         "start": {"line": 10}, "extra": {"message": "Synthetic unit fixture", "severity": "ERROR"}}], "errors": []}


def sarif():
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"rules": [{"id": "unit-sqli", "properties":
            {"problem.severity": "error", "precision": "high"}}]}}, "results": [{"ruleId": "unit-sqli",
            "message": {"text": "Synthetic unit fixture"}, "locations": [{"physicalLocation":
            {"artifactLocation": {"uri": "src/main/java/A.java"}, "region": {"startLine": 10}}}]}]}]}


def zap():
    return {"site": [{"alerts": [{"pluginid": "10001", "name": "Synthetic unit fixture", "riskcode": "1", "confidence": "2",
                                 "instances": [{"uri": "http://172.28.0.2:8080/actuator/health"}]}]}]}


class BoundaryTests(unittest.TestCase):
    def test_allowed_paths(self):
        for path in PATHS:
            self.assertEqual(check_url("http://172.28.0.2:8080" + path, "172.28.0.2"), path)

    def test_host_scheme_port_and_encoding_attacks(self):
        attacks = ["http://example.com:8080/actuator/health", "https://172.28.0.2:8080/actuator/health",
                   "http://172.28.0.2:80/actuator/health", "http://172.28.0.2:08080/actuator/health",
                   "http://localhost:8080/actuator/health", "http://127.0.0.1:8080/actuator/health",
                   "http://172.28.0.2.evil:8080/actuator/health", "http://evil@172.28.0.2:8080/actuator/health",
                   "http://172.28.0.2:8080/actuator/health?token=a", "http://172.28.0.2:8080/actuator/health#evil",
                   "http://172.28.0.2:8080/%61ctuator/health", "http://172.28.0.2:8080/%252e%252e/health",
                   "http://172.28.0.2:8080/../actuator/health", "http://172.28.0.2:8080//actuator/health",
                   "http://172.28.0.2:8080/actuator/health\r\nHost: evil", "http://172.28.0.2:8080\\evil",
                   "http://172.28.0.2.:8080/actuator/health", "http://[::1]:8080/actuator/health",
                   "http://2887516162:8080/actuator/health", "http://0254.034.0.2:8080/actuator/health",
                   "http://172.28.0.2:8080/api/labs/vuln002/articles/1"]
        for url in attacks:
            with self.subTest(url=url), self.assertRaises(ValueError):
                check_url(url, "172.28.0.2")

    def test_unknown_target(self):
        with self.assertRaises(ValueError):
            check_url("http://172.28.0.2:8080/actuator/health", "172.28.0.2", "other")

    def test_ip_boundaries(self):
        self.assertEqual(check_address("172.28.0.2", "172.28.0.0/24"), "172.28.0.2")
        for address in ("8.8.8.8", "127.0.0.1", "169.254.169.254", "172.29.0.2", "0.0.0.0", "::1", "172.28.0.0", "172.28.0.255"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                check_address(address, "172.28.0.0/24")

    def test_dns_exact(self):
        resolver = Mock(return_value=[(None, None, None, None, ("172.28.0.2", 8080))])
        resolve_exact("application", "172.28.0.2", resolver)
        resolver.return_value.append((None, None, None, None, ("172.28.0.3", 8080)))
        with self.assertRaises(ValueError):
            resolve_exact("application", "172.28.0.2", resolver)

    def test_dns_public_rebinding(self):
        resolver = Mock(return_value=[(None, None, None, None, ("8.8.8.8", 8080))])
        with self.assertRaises(ValueError):
            resolve_exact("application", "172.28.0.2", resolver)

    def test_redirect_refused_even_inside_scope(self):
        for status, loc in ((302, "http://example.com"), (301, "/actuator/health"), (307, None), (200, "/login")):
            with self.subTest(status=status), self.assertRaises(ValueError):
                reject_redirect(status, loc)
        reject_redirect(200, None)

    def test_docker_network_ownership_and_members(self):
        data = {"Name": "scan", "Driver": "bridge", "Internal": True, "EnableIPv6": False,
                "Labels": {LABEL: "run"}, "IPAM": {"Config": [{"Subnet": "172.28.0.0/24"}]},
                "Containers": {"x": {"Name": "guard"}}}
        self.assertEqual(validate_network(data, "scan", "run", ["guard"]), "172.28.0.0/24")
        for key, value in (("Internal", False), ("Driver", "host"), ("EnableIPv6", True), ("Labels", {}),
                           ("Containers", {"foreign": {"Name": "alien"}})):
            other = copy.deepcopy(data)
            other[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_network(other, "scan", "run", ["guard"])

    def test_container_identity(self):
        data = {"Name": "/application", "State": {"Running": True}, "Config": {"Labels": {LABEL: "run"}}, "Image": "sha256:known",
                "NetworkSettings": {"Networks": {"back": {"IPAddress": "172.28.0.2"}}},
                "HostConfig": {"ReadonlyRootfs": True, "Privileged": False, "PortBindings": {}, "CapAdd": None}, "Mounts": []}
        validate_container(data, "application", "run", "sha256:known", {"back": "172.28.0.0/24"}, [])
        for key, value in (("Image", "other"), ("Name", "/foreign"), ("Config", {"Labels": {}})):
            other = copy.deepcopy(data)
            other[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_container(other, "application", "run", "sha256:known", {"back": "172.28.0.0/24"}, [])
        for key, value in (("Privileged", True), ("ReadonlyRootfs", False), ("PortBindings", {"8080/tcp": []}), ("CapAdd", ["NET_ADMIN"])):
            other = copy.deepcopy(data)
            other["HostConfig"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_container(other, "application", "run", "sha256:known", {"back": "172.28.0.0/24"}, [])

    def test_guard_no_follow_redirect_and_response_limit(self):
        response = Mock(status=302)
        response.getheader.return_value = "http://example.com"
        connection = Mock()
        connection.getresponse.return_value = response
        with patch.object(guard, "resolve_exact"), patch.object(guard.http.client, "HTTPConnection", return_value=connection):
            with self.assertRaises(ValueError):
                guard.exchange("/actuator/health", "application", "172.28.0.2", "172.28.0.0/24")
            connection.request.assert_called_once()
            response.read.assert_not_called()
            connection.close.assert_called_once()

    def test_guard_dns_change_prevents_request(self):
        with patch.object(guard, "resolve_exact", side_effect=ValueError("Changed")), patch.object(guard.http.client, "HTTPConnection") as connection:
            with self.assertRaises(ValueError):
                guard.exchange("/actuator/health", "application", "172.28.0.2", "172.28.0.0/24")
            connection.assert_not_called()

    def test_passive_plan_has_no_active_or_crawler(self):
        text = plan("172.28.0.2")
        self.assertNotIn("type: activeScan", text)
        self.assertNotIn("type: spider", text)
        self.assertEqual(text.count("method: GET"), 5)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run = Run(self.temp.name, secrets=["unit-secret-value"])

    def test_actual_command_redaction(self):
        log = self.run.command([sys.executable, "-c", "import sys; print('unit-secret-value'); print('Cookie: abc',file=sys.stderr)"], "ok")
        text = log.read_text()
        self.assertNotIn("unit-secret-value", text)
        self.assertNotIn("abc", text)
        self.assertIn("REDACTED", text)

    def test_missing_tool(self):
        with self.assertRaises(CommandError) as caught:
            self.run.command(["nonexistent-unit-tool-123"], "missing")
        self.assertIsNone(caught.exception.record["exit_code"])
        self.assertEqual(caught.exception.record["execution_status"], "FAILED")

    def test_nonzero_tool(self):
        with self.assertRaises(CommandError) as caught:
            self.run.command([sys.executable, "-c", "raise SystemExit(7)"], "failure")
        self.assertEqual(caught.exception.record["exit_code"], 7)

    def test_timeout(self):
        with self.assertRaises(CommandError) as caught:
            self.run.command([sys.executable, "-c", "import time; time.sleep(5)"], "timeout", timeout=0.1)
        self.assertEqual(caught.exception.record["execution_status"], "TIMED_OUT")
        self.assertIsNone(caught.exception.record["exit_code"])

    def test_finite_retry(self):
        with self.assertRaises(CommandError):
            self.run.command([sys.executable, "-c", "raise SystemExit(2)"], "retry", retries=1)
        self.assertEqual(len(self.run.commands), 2)
        self.assertNotEqual(self.run.commands[0]["evidence_reference"], self.run.commands[1]["evidence_reference"])

    def test_interruption_recorded(self):
        with patch("labscan.core.subprocess.Popen", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run.command(["unit"], "interrupted")
        self.assertEqual(self.run.commands[0]["execution_status"], "INTERRUPTED")

    def test_history_not_overwritten(self):
        first = self.run.command([sys.executable, "-c", "print('one')"], "repeat")
        second = self.run.command([sys.executable, "-c", "print('two')"], "repeat")
        self.assertNotEqual(first, second)
        self.assertEqual(first.read_text().strip(), "one")
        other = Run(self.temp.name, [])
        self.assertNotEqual(self.run.id, other.id)

    def test_manifest_detects_tampering_and_traversal(self):
        log = self.run.command([sys.executable, "-c", "print('original')"], "manifest")
        manifest = self.run.manifest([log])
        verify_evidence(self.run.path, manifest)
        log.write_text("changed")
        with self.assertRaises(ValueError):
            verify_evidence(self.run.path, manifest)
        with self.assertRaises(ValueError):
            verify_evidence(self.run.path, [{"path": "../outside", "sha256": "anything"}])

    def test_redaction_nested_and_url(self):
        value = {"password": "abc", "items": ["Authorization: Bearer abc\n", "http://user:pass@host", "token=abc&x=1"]}
        text = json.dumps(redact(value))
        self.assertNotIn("abc", text)
        self.assertNotIn("user:pass", text)

    def test_write_once_json(self):
        path = self.run.path / "record.json"
        write_json(path, {"status": "first"})
        with self.assertRaises(FileExistsError):
            write_json(path, {"status": "second"})

    def test_invalid_retry_limits(self):
        with self.assertRaises(ValueError):
            self.run.command(["unit"], "invalid", retries=3)


class ParserTests(unittest.TestCase):
    def test_semgrep_normal(self):
        rows = parse_semgrep(semgrep(), "unit.json", "revision", "run", "vulnerable")
        self.assertEqual(rows[0]["severity"], "high")
        self.assertIsNone(rows[0]["confidence"])
        self.assertIn("confidence", rows[0]["null_reasons"])

    def test_sarif_normal(self):
        rows = parse_codeql(sarif(), "unit.sarif", "revision", "run", "vulnerable")
        self.assertEqual(rows[0]["confidence"], "high")
        self.assertEqual(rows[0]["source_location"]["line"], 10)

    def test_zap_normal(self):
        rows = parse_zap(zap(), "unit.json", "revision", "run", "172.28.0.2")
        self.assertEqual(rows[0]["severity"], "low")
        self.assertEqual(rows[0]["target_url"], "http://vulnerable-baseline:8080/actuator/health")

    def test_empty_is_valid_but_missing_is_error(self):
        self.assertEqual(parse_semgrep({"results": [], "errors": []}, "x", "r", "i", "vulnerable"), [])
        self.assertEqual(parse_codeql({"version": "2.1.0", "runs": []}, "x", "r", "i", "vulnerable"), [])
        self.assertEqual(parse_zap({"site": []}, "x", "r", "i"), [])
        for function, args in ((parse_semgrep, ("vulnerable",)), (parse_codeql, ("vulnerable",)), (parse_zap, ())):
            with self.assertRaises((ValueError, KeyError)):
                function({}, "x", "r", "i", *args)

    def test_tool_errors_never_empty_success(self):
        data = semgrep()
        data["errors"] = [{"message": "Failed"}]
        with self.assertRaises(ValueError):
            parse_semgrep(data, "x", "r", "i", "vulnerable")
        data = sarif()
        data["runs"][0]["invocations"] = [{"executionSuccessful": False}]
        with self.assertRaises(ValueError):
            parse_codeql(data, "x", "r", "i", "vulnerable")

    def test_invalid_source_and_line(self):
        for path in ("../A.java", "file:///C:/A.java", "src/main/java/%2e%2e/A.java", "apps/secure-app/src/main/java/A.java"):
            data = semgrep()
            data["results"][0]["path"] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                parse_semgrep(data, "x", "r", "i", "vulnerable")
        for line in (0, -1, "10", True):
            data = semgrep()
            data["results"][0]["start"]["line"] = line
            with self.assertRaises(ValueError):
                parse_semgrep(data, "x", "r", "i", "vulnerable")

    def test_zap_out_of_scope(self):
        data = zap()
        data["site"][0]["alerts"][0]["instances"][0]["uri"] = "http://example.com:8080/actuator/health"
        with self.assertRaises(ValueError):
            parse_zap(data, "x", "r", "i", "172.28.0.2")

    def test_unknown_metadata_null_reason(self):
        data = zap()
        data["site"][0]["alerts"][0].update(riskcode="unknown", confidence="unknown")
        row = parse_zap(data, "x", "r", "i")[0]
        self.assertIsNone(row["severity"])
        self.assertTrue(row["null_reasons"]["severity"])

    def test_duplicate_and_fingerprint_stable_across_runs(self):
        a = parse_semgrep(semgrep(), "a", "r1", "i1", "vulnerable")[0]
        b = parse_semgrep(semgrep(), "b", "r2", "i2", "vulnerable")[0]
        self.assertEqual(a["fingerprint"], b["fingerprint"])
        result = deduplicate([a, b])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["occurrences"], 2)
        self.assertEqual(result[0]["evidence_reference"], ["a", "b"])

    def test_different_tools_not_assumed_independent_vulnerabilities(self):
        a = parse_semgrep(semgrep(), "x", "r", "i", "vulnerable")
        b = parse_codeql(sarif(), "x", "r", "i", "vulnerable")
        self.assertNotEqual(a[0]["fingerprint"], b[0]["fingerprint"])

    def test_correlation(self):
        old = parse_semgrep(semgrep(), "x", "r", "old", "vulnerable")
        new = parse_semgrep(semgrep(), "x", "r", "new", "vulnerable")
        self.assertEqual(correlate(new, old)[0]["correlation"], "previously-observed")

    def test_json_malformed_duplicates_nonfinite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unit.json"
            for text in ('{broken', '{"a":1,"a":2}', '{"a":NaN}'):
                path.write_text(text)
                with self.assertRaises(ValueError):
                    load_json(path)


class WorkflowTests(unittest.TestCase):
    def test_regression_setup_preserves_sealed_helper_logs(self):
        run = Mock()
        module = phase3(run)
        module.run([sys.executable, "labs/VULN-002-IDOR/manage.py", "up"], "setup")
        self.assertEqual(run.command.call_args[0][0], [sys.executable, str(ROOT / "automation/regression_setup.py")])
    def test_invalid_resume_identifier(self):
        for name in ("../evil", "..", "evil/child", "evil\\child"):
            with self.assertRaises(ValueError):
                previous_run(name)

    def test_target_rejection_before_preflight(self):
        with tempfile.TemporaryDirectory() as directory, patch("labscan.workflow.Run", side_effect=lambda: Run(directory, [])), \
                patch("labscan.workflow.protected"), patch("labscan.workflow.preflight") as preflight:
            run, report = execute(["zap"], target="example.com")
            self.assertEqual(report["execution_status"], "FAILED")
            self.assertIsNone(report["steps"][2]["finding_count"])
            preflight.assert_not_called()

    def test_dry_run_is_not_scan_success(self):
        with tempfile.TemporaryDirectory() as directory, patch("labscan.workflow.Run", side_effect=lambda: Run(directory, [])), \
                patch("labscan.workflow.protected"), patch("labscan.workflow.preflight", return_value=({}, {})), \
                patch("labscan.workflow.phase3") as detector:
            _, report = execute(["semgrep"], dry_run=True)
            self.assertEqual(report["execution_status"], "NOT_EXECUTED")
            self.assertEqual(report["findings"], [])
            detector.return_value.semgrep.assert_not_called()

    def test_report_failure_cannot_have_zero_findings(self):
        report = {"schema_version": "1.0", "run_id": "i", "source_revision": "r", "execution_status": "FAILED",
                  "findings": [], "steps": [{"tool": t, "execution_status": "FAILED", "finding_count": 0} for t in ("semgrep", "codeql", "zap")]}
        with self.assertRaises(ValueError):
            validate_report(report)

    def test_partial_failure_preserves_completed_evidence_and_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            def detector(run):
                module = Mock()
                def semgrep_success():
                    for variant in ("vulnerable", "secure"):
                        write_json(module.OUT / f"semgrep-{variant}.json", semgrep() if variant == "vulnerable" else {"results": [], "errors": []})
                    return {"fixture": True}
                module.semgrep.side_effect = semgrep_success
                module.codeql.side_effect = RuntimeError("Synthetic failure")
                return module
            with patch("labscan.workflow.Run", side_effect=lambda: Run(directory, [])), patch("labscan.workflow.protected"), \
                    patch("labscan.workflow.preflight", return_value=({"fixture": "unit"}, {})), patch("labscan.workflow.phase3", side_effect=detector), \
                    patch("labscan.workflow.OUT", Path(directory)):
                first, report = execute(["semgrep", "codeql"], retries=0)
                self.assertEqual(report["execution_status"], "PARTIAL")
                self.assertEqual(report["steps"][0]["finding_count"], 1)
                self.assertIsNone(report["steps"][1]["finding_count"])
                before = sha(first.path / "report.json")
                child, resumed = execute(["semgrep", "codeql"], resume=first.id, retries=0)
                self.assertEqual(resumed["steps"][0]["execution_mode"], "historical-reuse")
                self.assertEqual(resumed["execution_status"], "PARTIAL")
                self.assertEqual(sha(first.path / "report.json"), before)
                # Simulate a hard stop after a validated checkpoint, before final report publication.
                (first.path / "report.json").unlink()
                recovered_dir, recovered = previous_run(first.id)
                self.assertEqual(recovered["steps"][0]["execution_status"], "COMPLETED")
                (first.path / "semgrep-vulnerable.json").write_text('{"results":[],"errors":[]}')
                _, rejected = execute(["semgrep", "codeql"], resume=first.id)
                self.assertEqual(rejected["execution_status"], "FAILED")
                self.assertIn("integrity", rejected["failure"])

    def test_interrupted_workflow_retains_static_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            def detector(run):
                module = Mock()
                def success():
                    for variant in ("vulnerable", "secure"):
                        write_json(module.OUT / f"semgrep-{variant}.json", {"results": [], "errors": []})
                    return {}
                module.semgrep.side_effect = success
                module.codeql.side_effect = KeyboardInterrupt
                return module
            with patch("labscan.workflow.Run", side_effect=lambda: Run(directory, [])), patch("labscan.workflow.protected"), \
                    patch("labscan.workflow.preflight", return_value=({}, {})), patch("labscan.workflow.phase3", side_effect=detector):
                run, report = execute(["semgrep", "codeql"], retries=0)
                self.assertEqual(report["execution_status"], "INTERRUPTED")
                self.assertEqual(report["steps"][0]["execution_status"], "COMPLETED")
                self.assertEqual(report["steps"][1]["execution_status"], "INTERRUPTED")
                self.assertTrue((run.path / 'report.json').exists())


if __name__ == "__main__":
    unittest.main()
