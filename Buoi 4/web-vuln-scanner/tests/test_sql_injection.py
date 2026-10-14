from scanners.sql_injection_tester import SQLInjectionTester
def test_probe_values_are_non_destructive():
    tester=SQLInjectionTester()
    assert tester.probes and all("DROP" not in p.upper() and "DELETE" not in p.upper() for p in tester.probes)
def test_error_signatures_are_detected():
    tester=SQLInjectionTester()
    assert tester._has_sql_error("You have an error in your SQL syntax")
    assert not tester._has_sql_error("Search complete")
