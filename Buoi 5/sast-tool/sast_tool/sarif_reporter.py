import json
import re
from pathlib import Path


class SarifReporter:
    LEVELS = {"high": "error", "medium": "warning", "low": "note"}

    @staticmethod
    def _rule_id(issue):
        value = issue.get("rule_id") or issue.get("type", "Finding")
        return re.sub(r"[^A-Za-z0-9_.-]", "_", value)

    def generate_report(self, issues, output_file="report.sarif", analyzed_file="input.py"):
        findings = list(issues)
        rule_ids = sorted({self._rule_id(item) for item in findings})
        indexes = {rule_id: index for index, rule_id in enumerate(rule_ids)}
        rules = [
            {"id": rule_id, "shortDescription": {"text": rule_id.replace("_", " ")}}
            for rule_id in rule_ids
        ]

        results = []
        uri = Path(analyzed_file).resolve().as_uri()
        for issue in findings:
            rule_id = self._rule_id(issue)
            results.append({
                "ruleId": rule_id,
                "ruleIndex": indexes[rule_id],
                "level": self.LEVELS.get(issue.get("severity", "medium").lower(), "warning"),
                "message": {"text": issue.get("message", "Security finding")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {
                            "startLine": max(1, int(issue.get("lineno", 1))),
                            "startColumn": max(1, int(issue.get("col_offset", 1))),
                        },
                    }
                }],
            })

        report = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Lab05-SAST", "rules": rules}},
                "results": results,
            }],
        }
        destination = Path(output_file)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        return destination
