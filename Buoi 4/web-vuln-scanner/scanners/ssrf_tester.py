import requests
from scanners.scope import is_allowed_target

class SSRFTester:
    probe_url = "http://127.0.0.1:1/"
    def __init__(self, timeout=4.0): self.timeout = timeout
    def _is_allowed_target(self, url): return is_allowed_target(url)
    def scan(self, endpoint, parameter="url"):
        if not self._is_allowed_target(endpoint): raise ValueError("Target is outside the authorized lab scope")
        response = requests.get(endpoint, params={parameter:self.probe_url}, timeout=self.timeout, allow_redirects=False)
        body = response.text.lower()
        signals = ("connection refused", "failed to connect", "errno 111", "127.0.0.1:1")
        if any(signal in body for signal in signals):
            return [{"type":"SSRF","severity":"high","url":response.url,"description":"Response reflects a loopback probe connection error, suggesting server-side fetching.","recommendation":"Use outbound destination allowlists, block private ranges, and revalidate redirects."}]
        return []
