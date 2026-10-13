"""PoC boundary/result checks, without network requests or subprocess execution."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("vuln001_verify", Path(__file__).with_name("verify.py"))
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)

class VerifyTest(unittest.TestCase):
    def test_expected_results_are_compared_by_identity(self):
        verify.require_ids([{"id": 1}], [1])
        verify.require_ids([], [])
        with self.assertRaises(AssertionError):
            verify.require_ids([{"id": 3}], [1])

    def test_redirects_are_blocked(self):
        self.assertIsNone(verify.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://example.com"))

    def test_target_is_fixed_loopback(self):
        self.assertEqual(verify.BASE, "http://127.0.0.1:8080")
        with self.assertRaises(ValueError):
            verify.Client().request("GET", "https://example.com", 200)

    def test_secure_regression_rejects_nonlocal_database(self):
        with patch.dict(verify.os.environ, {"VULN001_TEST_DB_URL": "jdbc:mysql://example.com/lab"}, clear=True):
            with self.assertRaises(ValueError):
                verify.secure_regression()

    def test_secure_regression_requires_environment_password(self):
        with patch.dict(verify.os.environ, {"VULN001_TEST_DB_URL": verify.MYSQL_URL,
                "VULN001_TEST_DB_USERNAME": "vuln001_reader"}, clear=True):
            with self.assertRaises(ValueError):
                verify.secure_regression()

    def test_no_arbitrary_target_or_payload_arguments(self):
        with patch.object(verify.sys, "argv", ["verify.py", "https://example.com"]):
            with self.assertRaises(ValueError):
                verify.main()

if __name__ == "__main__":
    unittest.main()
