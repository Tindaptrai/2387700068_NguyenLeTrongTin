from scanners.ssrf_tester import SSRFTester
def test_internal_probe_uses_loopback_only():
    assert SSRFTester.probe_url=="http://127.0.0.1:1/"
    assert "169.254.169.254" not in SSRFTester.probe_url
def test_target_scope_rejects_public_hosts():
    tester=SSRFTester()
    assert tester._is_allowed_target("http://127.0.0.1:5000/")
    assert not tester._is_allowed_target("https://example.com/")
