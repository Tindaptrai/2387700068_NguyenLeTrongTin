import json
import tempfile
import unittest
from pathlib import Path

from sast_tool.security_rule_engine import SecurityRuleEngine


class TestSecurityRuleEngine(unittest.TestCase):
    def test_applies_configured_severity(self):
        with tempfile.TemporaryDirectory() as folder:
            rules_path = Path(folder) / "rules.json"
            rules_path.write_text(
                json.dumps([{"type": "Use of eval", "severity": "high"}]),
                encoding="utf-8",
            )
            engine = SecurityRuleEngine(rules_path)
        findings = engine.evaluate([{"type": "Use of eval"}], [])
        self.assertEqual(findings[0]["severity"], "high")
