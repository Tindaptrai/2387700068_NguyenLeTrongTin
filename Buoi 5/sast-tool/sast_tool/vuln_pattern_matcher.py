import re


class VulnPatternMatcher:
    PATTERNS = (
        ("hardcoded_password",
         re.compile(r"""(?im)^[ \t]*(?:password|passwd)[ \t]*=[ \t]*(['"]).+?\1"""),
         "Hard-coded password detected."),
        ("pickle_import",
         re.compile(r"(?im)^[ \t]*(?:import[ \t]+pickle\b|from[ \t]+pickle\b)"),
         "Importing pickle can be unsafe for untrusted data."),
    )

    def match(self, code: str) -> list[dict]:
        issues = []
        for name, regex, message in self.PATTERNS:
            for found in regex.finditer(code):
                line = code.count("\n", 0, found.start()) + 1
                start = code.rfind("\n", 0, found.start()) + 1
                issues.append({
                    "type": "Pattern Match",
                    "pattern": name,
                    "message": message,
                    "lineno": line,
                    "col_offset": found.start() - start + 1,
                })
        return sorted(issues, key=lambda item: (item["lineno"], item["col_offset"]))
