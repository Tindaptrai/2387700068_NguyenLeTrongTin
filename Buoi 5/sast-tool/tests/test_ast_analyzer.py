import unittest

from sast_tool.ast_analyzer import ASTAnalyzer


class TestASTAnalyzer(unittest.TestCase):
    def test_detects_eval_call(self):
        findings = ASTAnalyzer().analyze("result = eval('1 + 1')")
        self.assertTrue(any(item["type"] == "Use of eval" for item in findings))

    def test_reports_syntax_error(self):
        findings = ASTAnalyzer().analyze("def broken(:")
        self.assertEqual(findings[0]["type"], "Syntax Error")
