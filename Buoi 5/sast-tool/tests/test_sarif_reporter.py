import json
import tempfile
import unittest
from pathlib import Path

from sast_tool.sarif_reporter import SarifReporter


class TestSarifReporter(unittest.TestCase):
    def test_writes_sarif_21_report(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "report.sarif"
            SarifReporter().generate_report(
                [{
                    "type": "Use of eval",
                    "severity": "high",
                    "message": "Do not use eval.",
                    "lineno": 2,
                    "col_offset": 3,
                }],
                output_file=destination,
                analyzed_file="sample.py",
            )
            report = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(report["version"], "2.1.0")
        self.assertEqual(report["runs"][0]["results"][0]["level"], "error")
