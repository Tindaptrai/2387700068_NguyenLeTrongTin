import unittest

from sast_tool.vuln_pattern_matcher import VulnPatternMatcher


class TestVulnPatternMatcher(unittest.TestCase):
    def test_finds_hardcoded_password(self):
        findings = VulnPatternMatcher().match('password = "demo-secret"')
        self.assertTrue(any(item["pattern"] == "hardcoded_password" for item in findings))

    def test_finds_pickle_import(self):
        findings = VulnPatternMatcher().match("import pickle")
        self.assertTrue(any(item["pattern"] == "pickle_import" for item in findings))

    def test_reports_matching_lines_after_blank_lines(self):
        code = ('\n\npassword = "demo-secret"\n\n'
                'import pickle\n\nfrom pickle import loads\n')
        findings = VulnPatternMatcher().match(code)
        self.assertEqual(
            [(item["pattern"], item["lineno"]) for item in findings],
            [("hardcoded_password", 3), ("pickle_import", 5), ("pickle_import", 7)],
        )
