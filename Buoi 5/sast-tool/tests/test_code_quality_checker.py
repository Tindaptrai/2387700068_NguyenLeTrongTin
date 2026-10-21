import tempfile
import unittest
from pathlib import Path

from sast_tool.code_quality_checker import CodeQualityChecker


class TestCodeQualityChecker(unittest.TestCase):
    def test_finds_flake8_issue(self):
        with tempfile.TemporaryDirectory() as folder:
            sample = Path(folder) / "sample.py"
            sample.write_text("import os\n", encoding="utf-8")
            findings = CodeQualityChecker().check(sample)
        self.assertTrue(any(item["type"] == "Lint Issue" for item in findings))
