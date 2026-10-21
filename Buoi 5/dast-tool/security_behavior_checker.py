import re
from pathlib import Path


class SecurityBehaviorChecker:
    PATTERNS = {
        "os.system": re.compile(r"\bos\.system\s*\("),
        "eval": re.compile(r"\beval\s*\("),
        "exec": re.compile(r"\bexec\s*\("),
    }

    def suspicious_calls(self, file_path=None):
        path = Path(file_path or __file__)
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return []
        return [
            name for name, pattern in self.PATTERNS.items()
            if pattern.search(content)
        ]
