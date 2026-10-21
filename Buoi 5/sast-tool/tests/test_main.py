import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from sast_tool.main import main


class TestMain(unittest.TestCase):
    def test_writes_sarif_to_requested_output(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "sample.py"
            source.write_text(
                'import os\n\nresult = eval("1 + 1")\n', encoding="utf-8"
            )
            destination = Path(folder) / "reports" / "scan.sarif"
            with redirect_stdout(io.StringIO()):
                exit_code = main([str(source), "--output", str(destination)])
            self.assertEqual(exit_code, 0)
            report = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(report["version"], "2.1.0")
        results = report["runs"][0]["results"]
        self.assertTrue(any(item["ruleId"] == "Use_of_eval" for item in results))
        self.assertTrue(any(item["ruleId"] == "F401" for item in results))

    def test_missing_source_returns_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            missing_source = Path(folder) / "missing.py"
            destination = Path(folder) / "scan.sarif"
            with redirect_stdout(io.StringIO()):
                exit_code = main([str(missing_source), "-o", str(destination)])
            self.assertEqual(exit_code, 1)
            self.assertFalse(destination.exists())
