"""Regression tests for failure reporting and immutable command evidence."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("record", Path(__file__).with_name("phase3-command.py"))
record = importlib.util.module_from_spec(spec)
spec.loader.exec_module(record)


class CommandEvidenceTest(unittest.TestCase):
    def test_nonzero_is_failure_and_keeps_both_streams(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(record, "OUT", Path(temp)):
            with self.assertRaises(RuntimeError):
                record.run([sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(7)"], "failure")
            row = json.loads(Path(temp, "commands.jsonl").read_text())
            self.assertEqual(row["exit_code"], 7)
            text = Path(row["output"]).read_text()
            self.assertIn("out", text)
            self.assertIn("err", text)
            self.assertIsNotNone(row["failure"])

    def test_retry_does_not_overwrite_original_log(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(record, "OUT", Path(temp)):
            first = record.run([sys.executable, "-c", "print('first')"], "retry")
            second = record.run([sys.executable, "-c", "print('second')"], "retry")
            self.assertNotEqual(first, second)
            self.assertEqual(first.read_text().strip(), "first")
            self.assertEqual(second.read_text().strip(), "second")
            self.assertEqual(len(Path(temp, "commands.jsonl").read_text().splitlines()), 2)

    def test_missing_executable_is_not_a_clean_scan(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(record, "OUT", Path(temp)):
            with self.assertRaises(RuntimeError):
                record.run([str(Path(temp, "missing-program.exe"))], "missing")
            row = json.loads(Path(temp, "commands.jsonl").read_text())
            self.assertNotEqual(row["exit_code"], 0)
            self.assertIsNotNone(row["failure"])


if __name__ == "__main__":
    unittest.main()
