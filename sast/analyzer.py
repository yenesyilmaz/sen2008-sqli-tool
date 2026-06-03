# AST-based static analyzer for SQL injection. It looks for queries built in an
# unsafe way (concatenation, %, f-strings, .format()) and follows a query through
# one variable assignment into an execute() call (single-function taint).

import ast
import os
from dataclasses import dataclass
from typing import List, Optional, Tuple

# (vulnerability_type, severity, description, recommendation)
Classification = Tuple[str, str, str, str]

SQL_KEYWORDS = ("SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "FROM", "WHERE")


@dataclass
class SASTFinding:
    file_path: str
    line_number: int
    code_snippet: str
    vulnerability_type: str
    severity: str
    description: str
    recommendation: str


class SASTAnalyzer(ast.NodeVisitor):
    def __init__(self, source_code: str, file_path: str = "<unknown>"):
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.findings: List[SASTFinding] = []
        self._db_execute_methods = {"execute", "executemany", "raw", "query"}
        self._tainted: dict = {}

    def _snippet(self, lineno: int) -> str:
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _is_sql_string(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            upper = node.value.upper()
            return any(kw in upper for kw in SQL_KEYWORDS)
        return False

    def _add_operands(self, node: ast.expr) -> List[ast.expr]:
        # flatten a + b + c into [a, b, c]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._add_operands(node.left) + self._add_operands(node.right)
        return [node]

    def _classify(self, expr: ast.expr) -> Optional[Classification]:
        # f-string with an interpolated value:  f"... {x} ..."
        if isinstance(expr, ast.JoinedStr):
            has_sql = any(self._is_sql_string(p) for p in expr.values
                          if isinstance(p, ast.Constant))
            has_value = any(isinstance(p, ast.FormattedValue) for p in expr.values)
            if has_sql and has_value:
                return (
                    "f-string SQL Injection", "HIGH",
                    "User input is placed directly into a SQL string with an f-string.",
                    "Use a parameterized query: cursor.execute('... = %s', (value,)).",
                )

        # % formatting:  "<sql>" % value
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
            if self._is_sql_string(expr.left):
                return (
                    "%-format SQL Injection", "HIGH",
                    "SQL query built with % string formatting.",
                    "Use a parameterized query: cursor.execute('... = %s', (value,)).",
                )

        # concatenation:  <sql literal> + <something dynamic>
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            operands = self._add_operands(expr)
            has_sql = any(self._is_sql_string(o) for o in operands)
            has_dynamic = any(not isinstance(o, ast.Constant) for o in operands)
            if has_sql and has_dynamic:
                return (
                    "String Concatenation SQL Injection", "CRITICAL",
                    "SQL query built by joining a string with a variable.",
                    "Never concatenate input into SQL. Use parameterized queries.",
                )

        # str.format():  "<sql>".format(...)
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
            if expr.func.attr == "format" and self._is_sql_string(expr.func.value):
                return (
                    ".format() SQL Injection", "HIGH",
                    "SQL query built with the str.format() method.",
                    "Use a parameterized query instead of .format() for SQL.",
                )

        return None

    def visit_FunctionDef(self, node):
        # keep taint local to each function
        saved = self._tainted
        self._tainted = {}
        self.generic_visit(node)
        self._tainted = saved

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign):
        result = self._classify(node.value)
        if result:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._tainted[target.id] = result
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr in self._db_execute_methods:
            if node.args:
                arg = node.args[0]
                result = self._classify(arg)
                if result:
                    self._report(node.lineno, *result)
                elif isinstance(arg, ast.Name) and arg.id in self._tainted:
                    vuln_type, severity, desc, rec = self._tainted[arg.id]
                    self._report(
                        node.lineno, vuln_type, severity,
                        desc + " The unsafe query is built above and run here.",
                        rec,
                    )
        self.generic_visit(node)

    def _report(self, lineno, vuln_type, severity, description, recommendation):
        self.findings.append(SASTFinding(
            file_path=self.file_path,
            line_number=lineno,
            code_snippet=self._snippet(lineno),
            vulnerability_type=vuln_type,
            severity=severity,
            description=description,
            recommendation=recommendation,
        ))


def analyze_file(file_path: str) -> List[SASTFinding]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source, filename=file_path)
        analyzer = SASTAnalyzer(source, file_path)
        analyzer.visit(tree)
        return analyzer.findings
    except SyntaxError as e:
        print(f"[SAST] Syntax error in {file_path}: {e}")
        return []
    except Exception as e:
        print(f"[SAST] Could not analyze {file_path}: {e}")
        return []


def analyze_directory(directory: str) -> List[SASTFinding]:
    all_findings = []
    for root, _, files in os.walk(directory):
        for fname in files:
            if fname.endswith(".py"):
                all_findings.extend(analyze_file(os.path.join(root, fname)))
    return all_findings
