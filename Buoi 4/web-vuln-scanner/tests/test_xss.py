from scanners.xss_scanner import XSSScanner
def test_payloads_are_benign_markers():
    scanner=XSSScanner()
    assert scanner.payloads and all("alert" in p for p in scanner.payloads)
def test_reflection_detector_requires_exact_payload():
    scanner=XSSScanner()
    assert scanner._is_reflected("<script>alert(1)</script>","<script>alert(1)</script>")
    assert not scanner._is_reflected("<script>alert(2)</script>","<script>alert(1)</script>")
