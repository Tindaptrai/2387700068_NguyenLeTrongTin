import re
import tempfile


class VirtualSandbox:
    """Demo runner that permits echo only; it is not an OS sandbox."""

    ECHO = re.compile(r"\s*echo(?:\s+(.*))?\s*", re.IGNORECASE | re.DOTALL)
    MAX_LENGTH = 1024

    def run_isolated(self, command):
        if isinstance(command, (list, tuple)):
            command = " ".join(str(part) for part in command)
        if not isinstance(command, str) or len(command) > self.MAX_LENGTH:
            raise ValueError("Command must be a short string.")

        match = self.ECHO.fullmatch(command)
        if not match:
            raise PermissionError("Only the echo demo command is allowed.")

        output = (match.group(1) or "").strip()
        if len(output) >= 2 and output[0] == output[-1] and output[0] in {"'", '"'}:
            output = output[1:-1]
        with tempfile.TemporaryDirectory(prefix="dast-demo-"):
            return output + "\n", ""
