import argparse
from pathlib import Path

from sast_tool.ast_analyzer import ASTAnalyzer
from sast_tool.code_quality_checker import CodeQualityChecker
from sast_tool.sarif_reporter import SarifReporter
from sast_tool.security_rule_engine import SecurityRuleEngine
from sast_tool.vuln_pattern_matcher import VulnPatternMatcher


def analyze_file(file_path, output_file="report.sarif"):
    path = Path(file_path)
    code = path.read_text(encoding="utf-8")
    ast_issues = ASTAnalyzer().analyze(code)
    pattern_issues = VulnPatternMatcher().match(code)
    quality_issues = CodeQualityChecker().check(path)
    issues = SecurityRuleEngine().evaluate(ast_issues, pattern_issues, quality_issues)
    report = SarifReporter().generate_report(
        issues, output_file=output_file, analyzed_file=path
    )
    return issues, report


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Analyze Python source and write a SARIF report."
    )
    parser.add_argument("file_path", help="Python source file to analyze")
    parser.add_argument(
        "-o", "--output", default="report.sarif", help="SARIF output path"
    )
    args = parser.parse_args(argv)
    try:
        issues, report = analyze_file(args.file_path, output_file=args.output)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Analysis failed: {error}")
        return 1
    print(f"Analysis complete: {len(issues)} issue(s).")
    print(f"SARIF report saved to {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
