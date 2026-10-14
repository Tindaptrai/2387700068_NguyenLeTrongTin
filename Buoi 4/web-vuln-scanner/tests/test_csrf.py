from scanners.csrf_detector import CSRFDetector
def test_csrf_header_detection():
    detector=CSRFDetector()
    assert detector._has_csrf_protection({"X-CSRF-Token":"present"})
    assert not detector._has_csrf_protection({"Content-Type":"text/html"})
