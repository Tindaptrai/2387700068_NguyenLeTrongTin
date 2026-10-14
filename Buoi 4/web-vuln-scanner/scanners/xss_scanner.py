import requests
from scanners.scope import is_allowed_target

class XSSScanner:
    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    def __init__(self, timeout=4.0): self.timeout = timeout
    @staticmethod
    def _is_reflected(body, payload): return payload in body
    def scan(self, url, parameter="q"):
        if not is_allowed_target(url): raise ValueError("Target is outside the authorized lab scope")
        found = []
        for payload in self.payloads:
            response = requests.get(url, params={parameter: payload}, timeout=self.timeout, allow_redirects=False)
            if self._is_reflected(response.text, payload):
                found.append({"type":"XSS","severity":"medium","url":response.url,"description":"Test marker reflected without output encoding.","recommendation":"Apply context-aware output encoding and a restrictive Content-Security-Policy."})
        return found
