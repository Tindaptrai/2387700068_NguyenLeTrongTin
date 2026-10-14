import requests
from scanners.scope import is_allowed_target

class SQLInjectionTester:
    probes = ["'", '"', "')("]
    signatures = ("you have an error in your sql syntax", "sqlite error", "psql: error", "ora-", "sqlstate[", "unclosed quotation mark")
    def __init__(self, timeout=4.0): self.timeout = timeout
    def _has_sql_error(self, body): return any(sig in body.lower() for sig in self.signatures)
    def scan(self, url, parameter="q"):
        if not is_allowed_target(url): raise ValueError("Target is outside the authorized lab scope")
        for probe in self.probes:
            response = requests.get(url, params={parameter:probe}, timeout=self.timeout, allow_redirects=False)
            if self._has_sql_error(response.text):
                return [{"type":"SQLi","severity":"high","url":response.url,"description":"Database error signature appeared after a quote probe.","recommendation":"Use parameterized queries and return generic error messages."}]
        return []
