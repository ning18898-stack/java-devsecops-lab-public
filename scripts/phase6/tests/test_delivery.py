import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("delivery", Path(__file__).parents[1] / "ci.py")
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


class DeliveryTests(unittest.TestCase):
    def test_linux_mysql_init_copy_preserves_source_and_read_only_mount(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = ci.Run(tmp, secrets=[])
            source = ci.ROOT / 'infra/mysql/vuln002-init/001-init.sh'
            before = source.read_bytes()
            with patch.object(ci.sys, 'platform', 'linux'):
                arguments = ci.mysql_init_override(run)
            override = json.loads(Path(arguments[1]).read_text(encoding='utf-8'))
            mount = override['services']['mysql']['volumes'][0]
            copy = Path(mount['source']) / source.name
            self.assertEqual(copy.read_bytes(), before.replace(b'\r\n', b'\n'))
            self.assertEqual(source.read_bytes(), before)
            self.assertTrue(mount['read_only'])
            self.assertEqual(mount['target'], '/docker-entrypoint-initdb.d')
            if sys.platform == 'linux':
                self.assertTrue(copy.stat().st_mode & 0o111)

    def test_failure_and_timeout_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = ci.Run(tmp, secrets=["sensitive-test-value"])
            with self.assertRaises(Exception):
                run.command([sys.executable, "-c", "print('sensitive-test-value');raise SystemExit(7)"], "failure")
            self.assertEqual(run.commands[-1]["exit_code"], 7)
            self.assertNotIn("sensitive-test-value", next(run.path.glob('failure-*.log')).read_text())
            with self.assertRaises(Exception):
                run.command([sys.executable, "-c", "import time;time.sleep(10)"], "timeout", timeout=.1)
            self.assertEqual(run.commands[-1]["execution_status"], "TIMED_OUT")

    def test_publish_is_an_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = ci.Run(root / "private", secrets=["actual-secret-value"])
            (run.path / "result.json").write_text(json.dumps({"password": "actual-secret-value", "path": "C:/Users/person/secret"}))
            (run.path / "database.sqlite3").write_bytes(b'private database')
            (run.path / "trace.zip").write_bytes(b'private browser session')
            (run.path / "server.log").write_text('actual-secret-value')
            with patch.object(ci, "ROOT", root):
                dest = Path(ci.publish(run))
            self.assertEqual([p.name for p in dest.iterdir()], ["result.json"])
            self.assertNotIn("actual-secret-value", (dest / "result.json").read_text())
            self.assertNotIn("person", (dest / "result.json").read_text())

    def test_reviewed_manifest_and_contract(self):
        manifest = ci.load_json(ci.FIXTURES / "manifest.json")
        for name, digest in manifest["files"].items():
            self.assertEqual(ci.sha(ci.FIXTURES / name), digest)
        for run_id in ci.IDS:
            data = ci.load_json(ci.FIXTURES / run_id / "report.json")
            self.assertEqual(data["run_id"], run_id)
            self.assertEqual({s['tool']:s['finding_count'] for s in data['steps']}, {'semgrep':2,'codeql':3,'zap':0})
            for entry in data["evidence_manifest"]:
                self.assertEqual(ci.sha(ci.FIXTURES / run_id / entry['path']), entry['sha256'])

    def test_environment_excludes_experiment_overrides(self):
        with patch.dict(ci.os.environ, {"VULN002_ENABLED":"true", "SPRING_PROFILES_ACTIVE":"vuln002-local", "SEMGREP_APP_TOKEN":"do-not-send"}):
            env = ci.environment()
        self.assertNotIn("VULN002_ENABLED", env)
        self.assertNotIn("SPRING_PROFILES_ACTIVE", env)
        self.assertNotIn("SEMGREP_APP_TOKEN", env)

    def test_materialize_preserves_existing_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for run_id in ci.IDS:
                dest = root / "artifacts/phase4" / run_id
                dest.mkdir(parents=True)
                (dest / "report.json").write_text('immutable real evidence')
            with patch.object(ci, "ROOT", root):
                ci.materialize()
            self.assertEqual((dest / "report.json").read_text(), 'immutable real evidence')

    def test_zap_adapter_calls_sealed_api_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = ci.Run(tmp, secrets=[])
            report = run.path/'actual.json'
            report.write_text('{"site":[]}')
            closed = []
            class Sandbox:
                def __init__(self, run, lock):pass
                def start(self):pass
                def verify(self):pass
                def scan_zap(self):return report, '172.18.0.2'
                def close(self):closed.append(True)
            with patch('labscan.zap.Sandbox',Sandbox), patch.object(run,'command',return_value=report), patch.object(ci,'git',return_value='a'*40):
                result=ci.zap(run)
            self.assertEqual(result['observations'],0)
            self.assertEqual(closed,[True])
