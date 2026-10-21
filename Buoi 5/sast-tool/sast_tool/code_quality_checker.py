import re
import subprocess
import sys
from pathlib import Path


FLAKE8_LINE = re.compile(r"^(.*):(\d+):(\d+):\s*([A-Z]+\d+)\s+(.*)$")


class CodeQualityChecker:
    def check(self, filepath):
        path = Path(filepath)
        try:
            result = subprocess.run(
                [
                    sys.executable, "-m", "flake8",
                    "--format=%(path)s:%(row)d:%(col)d:%(code)s %(text)s",
                    str(path),
                ],
                capture_output=True, text=True, check=False,
            )
        except OSError as error:
            return [{
                "type": "Tool Error",
                "message": f"Could not start flake8: {error}",
                "lineno": 1,
                "col_offset": 1,
            }]

        lines = result.stdout.splitlines()
        if result.returncode and not lines and result.stderr:
            return [{
                "type": "Tool Error",
                "message": result.stderr.strip(),
                "lineno": 1,
                "col_offset": 1,
            }]

        issues = []
        for line in lines:
            match = FLAKE8_LINE.match(line)
            if match:
                _, row, column, rule_id, message = match.groups()
                issues.append({
                    "type": "Lint Issue",
                    "rule_id": rule_id,
                    "message": f"{rule_id}: {message}",
                    "lineno": int(row),
                    "col_offset": int(column),
                })
        return issues
