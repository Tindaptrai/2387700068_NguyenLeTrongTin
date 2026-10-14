from report.report_generator import ReportGenerator
def test_report_contains_findings_and_remediation():
    text=ReportGenerator().generate([{"type":"XSS","severity":"high","url":"http://127.0.0.1","description":"marker","recommendation":"Encode output"}])
    assert "XSS" in text and "Encode output" in text
