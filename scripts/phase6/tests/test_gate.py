import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).parents[1]))
import verify


class GateTests(unittest.TestCase):
    def test_failed_or_untimed_receipts_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'artifacts').mkdir();file=root/'artifacts/test.json'
            with patch.object(verify,'ROOT',root):
                for data in ({'status':'PASS','exit_code':0},{'status':'FAIL','exit_code':1,'started':'x','ended':'y'}):
                    file.write_text(json.dumps(data))
                    with self.assertRaises(ValueError):verify.receipt(file)

    def test_missing_modules_cannot_set_ready(self):
        with self.assertRaises(ValueError):verify.assemble({},None,None,None)

    def test_remote_status_stays_unverified(self):
        with patch.object(verify,'receipt',return_value={'status':'PASS','clean_checkout':True}):
            result=verify.assemble(dict.fromkeys(verify.REQUIRED,'receipt'),'integration','clean',None)
        self.assertTrue(result['PHASE6_LOCAL_READY'])
        self.assertFalse(result['PHASE6_READY'])
        self.assertEqual(result['matrix']['hosted_actions']['status'],'NOT_TESTED')
