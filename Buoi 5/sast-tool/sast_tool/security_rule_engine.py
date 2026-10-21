import json
from pathlib import Path


class SecurityRuleEngine:
    def __init__(self, rules_file=None):
        if rules_file is None:
            rules_file = Path(__file__).resolve().parent.parent / "rules" / "default_rules.json"
        with Path(rules_file).open("r", encoding="utf-8") as stream:
            self.rules = json.load(stream)

    def evaluate(self, ast_issues, pattern_issues, quality_issues=()):
        issues = [
            dict(issue)
            for issue in ast_issues + pattern_issues + list(quality_issues)
        ]
        for issue in issues:
            issue_type = issue.get("type", "")
            for rule in self.rules:
                rule_type = rule.get("type", "")
                if issue_type == rule_type or issue_type.startswith(rule_type):
                    issue["severity"] = rule.get("severity", "medium")
                    break
            else:
                issue["severity"] = "medium"
        return issues
