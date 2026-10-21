import ast


class ASTAnalyzer:
    DANGEROUS_CALLS = {"eval", "exec"}

    def analyze(self, code: str) -> list[dict]:
        try:
            tree = ast.parse(code)
        except SyntaxError as error:
            return [{
                "type": "Syntax Error",
                "message": error.msg,
                "lineno": error.lineno or 1,
                "col_offset": error.offset or 1,
            }]

        issues = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = None
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name in self.DANGEROUS_CALLS:
                issues.append({
                    "type": f"Use of {name}",
                    "message": f"Use of {name} can execute dynamic code and should be avoided.",
                    "lineno": node.lineno,
                    "col_offset": node.col_offset + 1,
                })
        return issues
