import unittest
from unittest.mock import patch
import db
import runtime as rt
import verify

class ToolSafetyTest(unittest.TestCase):
    def test_credential_initialization_preserves_existing_values(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory, patch.object(db,"ROOT",Path(directory)):
            first=db.credentials(True)
            self.assertEqual(first,db.credentials(True))
            self.assertEqual(set(first),set(db.KEYS))
            self.assertEqual(len(set(first.values())),4)

    def test_fixed_local_targets(self):
        self.assertEqual(set(rt.BASES.values()), {"http://127.0.0.1:8080","http://127.0.0.1:8081"})
        with self.assertRaises(ValueError): rt.Client("https://example.com")

    def test_client_rejects_non_api_and_traversal(self):
        client=rt.Client("vulnerable")
        for path in ("https://example.com", "/api/../external", "/actuator/env", "/api/x\n"):
            with self.assertRaises(ValueError): client.request("GET",path,200)

    def test_invalid_run_never_calls_database(self):
        with patch.object(db,"sql") as query:
            for value in ("", "x", "../", "0"*31, "0"*33, "';DELETE"):
                with self.assertRaises(ValueError): db.cleanup("vulnerable",value)
            query.assert_not_called()

    def test_other_database_or_role_rejected_before_process(self):
        with patch.object(db.subprocess,"run") as process:
            for suffix,role in (("lab","app"),("vulnerable","root"),("lab_vuln001","reader")):
                with self.assertRaises(ValueError): db.sql(suffix,role,"SELECT 1")
            process.assert_not_called()

    def test_cleanup_is_parameter_scoped_and_transactional(self):
        with patch.object(db,"sql") as query:
            run="a"*32; db.cleanup("secure",run)
            statement=query.call_args.args[2]
            self.assertEqual(statement.count("WHERE run_id="),2)
            self.assertIn("START TRANSACTION",statement)
            self.assertIn("COMMIT",statement)
            self.assertNotIn("TRUNCATE",statement)

    def test_sql_values_are_hex_encoded(self):
        value="'; DROP TABLE x; --"
        encoded=db.literal(value)
        self.assertNotIn(value,encoded)
        self.assertIn(value.encode().hex(),encoded)

    def test_redirect_is_rejected(self):
        self.assertIsNone(rt.NoRedirect().redirect_request(None,None,302,"",{},"https://example.com"))

    def test_evidence_rejects_changed_owner_or_refused_mutation(self):
        before = {"id": 1, "run_id": "a" * 32, "owner": 7, "title": "old",
            "content": "old", "created_at": "t0", "updated_at": "t1"}
        after = dict(before, title="new", content="new", updated_at="t2")
        verify.require_changed(before, after, "new", "new")
        with self.assertRaises(AssertionError):
            verify.require_changed(before, dict(after, owner=8), "new", "new")
        with self.assertRaises(AssertionError):
            verify.require_unchanged(before, after)

    def test_evidence_rejects_uncommitted_or_missing_timestamp_update(self):
        before = {"id": 1, "run_id": "a" * 32, "owner": 7, "title": "old",
            "content": "old", "created_at": "t0", "updated_at": "t1"}
        with self.assertRaises(AssertionError):
            verify.require_changed(before, before, "new", "new")
        with self.assertRaises(AssertionError):
            verify.require_changed(before, dict(before, title="new", content="new"), "new", "new")

if __name__=="__main__": unittest.main()
