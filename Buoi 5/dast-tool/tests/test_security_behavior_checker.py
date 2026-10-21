import tempfile
import unittest
from pathlib import Path

from security_behavior_checker import SecurityBehaviorChecker


class TestSecurityBehaviorChecker(unittest.TestCase):
    def test_detects_suspicious_call_text(self):
        with tempfile.TemporaryDirectory() as folder:
            sample = Path(folder) / "sample.py"
            sample.write_text('os.system("example")\n', encoding="utf-8")
            findings = SecurityBehaviorChecker().suspicious_calls(sample)
        self.assertIn("os.system", findings)
