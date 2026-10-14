import re
import requests
from scanners.scope import is_allowed_target

class CSRFDetector:
    def __init__(self, timeout=4.0): self.timeout = timeout
    def _has_csrf_protection(self, headers):
        return any("csrf" in key.lower() or "xsrf" in key.lower() for key in headers)
    def scan(self, url):
        if not is_allowed_target(url): raise ValueError("Target is outside the authorized lab scope")
        response = requests.get(url, timeout=self.timeout, allow_redirects=False)
        cookies = response.headers.get("Set-Cookie", "").lower()
        same_site = "samesite=strict" in cookies or "samesite=lax" in cookies
        forms = re.findall(r"<form\b[^>]*>(.*?)</form>", response.text, re.I | re.S)
        token = any(re.search(r"<input\b(?=[^>]*type=['\"]?hidden)(?=[^>]*(csrf|xsrf|authenticity))[^>]*>", f, re.I) for f in forms)
        if same_site or token or self._has_csrf_protection(response.headers) or not forms: return []
        return [{"type":"CSRF","severity":"medium","url":url,"description":"Forms found without a common CSRF token or SameSite cookie signal.","recommendation":"Validate an unpredictable CSRF token on state-changing requests and set SameSite cookies."}]
