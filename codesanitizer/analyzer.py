"""
analyzer.py - AST Code Analyzer for Python Security & Import Extraction
Part of CodeSanitizer - AI-Generated Code & Package Hallucination Auditor.

Analyzes Python code strictly using Python's built-in `ast` module.
NEVER executes submitted code. Treats all code as untrusted input.
"""

import ast
import re
from typing import Dict, List, Set, Tuple, Optional, Any
from rules import VulnerabilityFinding, Severity, calculate_security_score
from package_checker import normalize_package_name, run_package_verification, PackageVerificationResult

# Heuristics for Secret Variable Names
SECRET_NAME_PATTERNS = re.compile(
    r"(api[_-]?key|secret[_-]?key|access[_-]?key|token|auth[_-]?token|"
    r"private[_-]?key|client[_-]?secret|password|passwd|db[_-]?password|"
    r"jwt[_-]?secret|aws[_-]?secret|credentials)",
    re.IGNORECASE,
)

# Placeholders that are not real hardcoded secrets
SECRET_IGNORE_VALUES = {
    "", "placeholder", "your_api_key_here", "your_key", "your_secret",
    "test", "none", "null", "changeme", "secret", "password", "123456",
    "todo", "dummy", "sample"
}

# Common SQL Keywords to flag unsafe string concatenations
SQL_KEYWORDS = {"select", "insert", "update", "delete", "drop", "alter", "create", "where", "from", "union"}


class CodeSanitizerASTVisitor(ast.NodeVisitor):
    """
    Traverses the Python AST to discover dangerous functions, system commands,
    hardcoded secrets, SQL injection risks, and extract imports.
    """

    def __init__(self, source_lines: List[str]):
        self.source_lines = source_lines
        self.findings: List[VulnerabilityFinding] = []
        self.imports_map: Dict[str, List[int]] = {}  # {package_name: [lines]}

    def _get_snippet(self, node: ast.AST) -> str:
        """Safely extracts the source line or snippet for an AST node."""
        lineno = getattr(node, "lineno", 0)
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return "<code unavailable>"

    # -------------------------------------------------------------
    # 1. IMPORT EXTRACTION
    # -------------------------------------------------------------
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            raw_name = alias.name
            normalized = normalize_package_name(raw_name)
            if normalized:
                self.imports_map.setdefault(normalized, []).append(node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            normalized = normalize_package_name(node.module)
            if normalized:
                self.imports_map.setdefault(normalized, []).append(node.lineno)
        self.generic_visit(node)

    # -------------------------------------------------------------
    # 2. DANGEROUS FUNCTION CALLS & SYSTEM COMMANDS
    # -------------------------------------------------------------
    def visit_Call(self, node: ast.Call):
        func_name = ""
        full_call = ""

        # Extract function call name
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            full_call = func_name
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            # Check for module.func e.g., os.system, subprocess.run
            if isinstance(node.func.value, ast.Name):
                full_call = f"{node.func.value.id}.{func_name}"
            elif isinstance(node.func.value, ast.Attribute):
                full_call = f"...{node.func.value.attr}.{func_name}"

        snippet = self._get_snippet(node)

        # Check A: eval(), exec(), compile()
        if full_call in {"eval", "exec", "compile", "__import__"}:
            if full_call == "eval":
                self.findings.append(VulnerabilityFinding(
                    rule_id="DANGEROUS_FUNC_EVAL",
                    title="Dangerous Function: eval()",
                    severity="CRITICAL",
                    line=node.lineno,
                    code_snippet=snippet,
                    explanation="`eval()` parses and evaluates arbitrary Python expressions dynamically at runtime.",
                    why="Untrusted input passed to `eval()` allows attackers to execute arbitrary code with full process privileges.",
                    recommendation="Avoid `eval()`. Use safe parsing libraries like `ast.literal_eval` or json validation.",
                    vulnerable_example="result = eval(user_input)",
                    recommended_example="import ast\nresult = ast.literal_eval(user_input)  # Evaluates only safe literals",
                ))
            elif full_call == "exec":
                self.findings.append(VulnerabilityFinding(
                    rule_id="DANGEROUS_FUNC_EXEC",
                    title="Dangerous Function: exec()",
                    severity="CRITICAL",
                    line=node.lineno,
                    code_snippet=snippet,
                    explanation="`exec()` dynamically executes Python statements, bypassing static security controls.",
                    why="Any attacker input reaching `exec()` leads directly to Remote Code Execution (RCE) on the host.",
                    recommendation="Avoid `exec()`. Refactor code to use dictionary lookups, explicit control flow, or callable classes.",
                    vulnerable_example="exec(f'action_{user_action}()')",
                    recommended_example="ACTIONS = {'start': do_start, 'stop': do_stop}\nACTIONS.get(user_action, default_handler)()",
                ))
            elif full_call == "compile":
                self.findings.append(VulnerabilityFinding(
                    rule_id="DANGEROUS_FUNC_COMPILE",
                    title="Dynamic Compilation: compile()",
                    severity="HIGH",
                    line=node.lineno,
                    code_snippet=snippet,
                    explanation="`compile()` turns dynamic string expressions into executable bytecode.",
                    why="Compiling untrusted strings into code objects enables arbitrary logic injection and memory exploits.",
                    recommendation="Use static functions or domain-specific expression parsers instead of compiling dynamic code strings.",
                    vulnerable_example="code_obj = compile(untrusted_str, '<string>', 'exec')",
                    recommended_example="# Use predefined static functions or standard logic parsers",
                ))

        # Check B: Dangerous System Commands (os.system, subprocess.*)
        if full_call in {"os.system", "os.popen", "os.spawnl", "os.spawnle", "os.spawnlp"}:
            self.findings.append(VulnerabilityFinding(
                rule_id="DANGEROUS_SYS_OS_SYSTEM",
                title=f"Insecure System Execution: {full_call}()",
                severity="HIGH",
                line=node.lineno,
                code_snippet=snippet,
                explanation=f"`{full_call}()` passes a string command directly to the host operating system shell.",
                why="Vulnerable to shell command injection. Attackers can inject command separators (`;`, `&&`, `|`) to execute malicious host binaries.",
                recommendation="Replace `os.system()` with `subprocess.run([...], shell=False)` using tokenized arguments.",
                vulnerable_example="os.system('ping -c 1 ' + user_target)",
                recommended_example="import subprocess\nsubprocess.run(['ping', '-c', '1', user_target], check=True, shell=False)",
            ))

        elif full_call in {"subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"}:
            # Check if shell=True is passed
            has_shell_true = False
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    has_shell_true = True

            # Check if first arg is a formatted string or binary concatenation
            has_dynamic_first_arg = False
            if node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, (ast.JoinedStr, ast.BinOp)):
                    has_dynamic_first_arg = True

            if has_shell_true or has_dynamic_first_arg:
                self.findings.append(VulnerabilityFinding(
                    rule_id="DANGEROUS_SYS_SUBPROCESS",
                    title=f"Potentially Unsafe Command Invocation: {full_call}()",
                    severity="HIGH" if has_shell_true else "MEDIUM",
                    line=node.lineno,
                    code_snippet=snippet,
                    explanation=(
                        f"`{full_call}()` called with {'shell=True' if has_shell_true else 'dynamic string parameter'}. "
                        "Passing unescaped user data through the shell enables command injection."
                    ),
                    why="Shell interpreters expand metacharacters, allowing remote attackers to run arbitrary system commands.",
                    recommendation="Set `shell=False` and pass arguments as a list of strings: `subprocess.run(['cmd', arg], shell=False)`.",
                    vulnerable_example="subprocess.run(f'curl {url}', shell=True)",
                    recommended_example="subprocess.run(['curl', url], check=True, shell=False)",
                ))

        # Check C: Insecure Deserialization (pickle.loads)
        if full_call in {"pickle.loads", "pickle.load", "_pickle.loads"}:
            self.findings.append(VulnerabilityFinding(
                rule_id="INSECURE_DESERIALIZATION_PICKLE",
                title="Insecure Deserialization: pickle",
                severity="HIGH",
                line=node.lineno,
                code_snippet=snippet,
                explanation="`pickle` can deserialize arbitrary Python objects, including bytecode that executes system commands during unpacking.",
                why="Attackers can craft malicious pickle payloads that trigger arbitrary code execution upon loading.",
                recommendation="Use safe data interchange formats such as JSON, Protocol Buffers, or msgpack.",
                vulnerable_example="data = pickle.loads(untrusted_bytes)",
                recommended_example="import json\ndata = json.loads(untrusted_text)",
            ))

        # Check D: SQL Injection inside execute calls (e.g. cursor.execute("..." + var))
        if func_name == "execute" and node.args:
            first_arg = node.args[0]
            if self._is_unsafe_sql_node(first_arg):
                self.findings.append(VulnerabilityFinding(
                    rule_id="SQL_INJECTION_EXECUTE",
                    title="SQL Injection Risk in Database Execution",
                    severity="HIGH",
                    line=node.lineno,
                    code_snippet=snippet,
                    explanation="User-controlled data is formatted or concatenated directly into `cursor.execute()`.",
                    why="Allows attackers to manipulate SQL queries, bypass authentication, exfiltrate data, or tamper with tables.",
                    recommendation="Use parameterized queries with placeholders (`?` or `%s`) and pass values as a separate tuple.",
                    vulnerable_example='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                    recommended_example='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                ))

        self.generic_visit(node)

    # -------------------------------------------------------------
    # 3. HARDCODED SECRET DETECTION
    # -------------------------------------------------------------
    def visit_Assign(self, node: ast.Assign):
        self._check_secret_assignment(node.targets, node.value, node.lineno)
        self._check_sql_assignment(node.targets, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if node.value:
            self._check_secret_assignment([node.target], node.value, node.lineno)
            self._check_sql_assignment([node.target], node.value, node.lineno)
        self.generic_visit(node)

    def _check_secret_assignment(self, targets: List[ast.AST], value_node: ast.AST, lineno: int):
        """Inspects variable assignments for hardcoded secrets."""
        for target in targets:
            var_name = ""
            if isinstance(target, ast.Name):
                var_name = target.id
            elif isinstance(target, ast.Attribute):
                var_name = target.attr

            if not var_name:
                continue

            if SECRET_NAME_PATTERNS.search(var_name):
                # Check if assigned value is a string constant
                if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
                    secret_val = value_node.value.strip()
                    # Filter out placeholders, empty strings, or very short values
                    if len(secret_val) >= 4 and secret_val.lower() not in SECRET_IGNORE_VALUES:
                        # Mask the secret for safe display
                        if len(secret_val) <= 6:
                            masked_val = "***"
                        else:
                            masked_val = secret_val[:3] + "***" + secret_val[-2:]

                        snippet = self._get_snippet(value_node)
                        # Replace raw secret in snippet for report security
                        safe_snippet = re.sub(re.escape(secret_val), masked_val, snippet)

                        self.findings.append(VulnerabilityFinding(
                            rule_id="HARDCODED_SECRET",
                            title=f"Hardcoded Secret Detected: `{var_name}`",
                            severity="HIGH",
                            line=lineno,
                            code_snippet=safe_snippet,
                            explanation=f"Variable `{var_name}` appears to hold a hardcoded sensitive secret/credential.",
                            why="Hardcoding API keys or passwords commits sensitive secrets into version control, risking credential theft and account compromise.",
                            recommendation="Load secrets from environment variables or a secure key management vault.",
                            vulnerable_example=f'{var_name} = "{masked_val}"',
                            recommended_example=f'import os\n{var_name} = os.getenv("{var_name}")',
                            secret_var=var_name,
                        ))

    # -------------------------------------------------------------
    # 4. SQL INJECTION IN STRING ASSIGNMENTS
    # -------------------------------------------------------------
    def _is_unsafe_sql_node(self, node: ast.AST) -> bool:
        """Checks if an AST node contains an unsafe SQL string construction."""
        # 1. F-Strings: f"SELECT ... {var}"
        if isinstance(node, ast.JoinedStr):
            has_sql_kw = False
            has_var = False
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    text_lower = part.value.lower()
                    if any(kw in text_lower for kw in SQL_KEYWORDS):
                        has_sql_kw = True
                elif isinstance(part, ast.FormattedValue):
                    has_var = True
            if has_sql_kw and has_var:
                return True

        # 2. Binary operations: "SELECT ... " + var
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            has_sql_kw = False
            has_var = False
            # Check left and right
            for child in (node.left, node.right):
                if isinstance(child, ast.Constant) and isinstance(child.value, str):
                    text_lower = child.value.lower()
                    if any(kw in text_lower for kw in SQL_KEYWORDS):
                        has_sql_kw = True
                elif isinstance(child, (ast.Name, ast.Call, ast.Attribute, ast.Subscript)):
                    has_var = True
                elif isinstance(child, ast.BinOp):
                    if self._is_unsafe_sql_node(child):
                        return True
            if has_sql_kw and has_var:
                return True

        # 3. Old string formatting: "SELECT ... %s" % var
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                text_lower = node.left.value.lower()
                if any(kw in text_lower for kw in SQL_KEYWORDS):
                    return True

        # 4. str.format(): "SELECT ... {}".format(var)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                text_lower = node.func.value.value.lower()
                if any(kw in text_lower for kw in SQL_KEYWORDS):
                    return True

        return False

    def _check_sql_assignment(self, targets: List[ast.AST], value_node: ast.AST, lineno: int):
        """Detects SQL injection patterns in variable assignments."""
        for target in targets:
            var_name = getattr(target, "id", "") or getattr(target, "attr", "")
            # If variable name suggests a query or the value is clearly an unsafe SQL string
            is_query_var = any(term in var_name.lower() for term in ["query", "sql", "statement", "stmt"])
            
            if self._is_unsafe_sql_node(value_node):
                snippet = self._get_snippet(value_node)
                self.findings.append(VulnerabilityFinding(
                    rule_id="SQL_INJECTION_ASSIGNMENT",
                    title="SQL Injection Risk: Dynamic SQL Query Construction",
                    severity="HIGH",
                    line=lineno,
                    code_snippet=snippet,
                    explanation="Dynamic variable interpolation detected within an SQL statement string.",
                    why="Direct string concatenation or f-strings in SQL queries allow attackers to inject arbitrary SQL syntax.",
                    recommendation="Parameterize all database queries. Do not concatenate or format variables into SQL strings.",
                    vulnerable_example='query = f"SELECT * FROM users WHERE name = \'{user}\'"\ncursor.execute(query)',
                    recommended_example='query = "SELECT * FROM users WHERE name = ?"\ncursor.execute(query, (user,))',
                ))
                break


def analyze_python_code(code_str: str) -> Dict[str, Any]:
    """
    Primary analysis engine for CodeSanitizer.
    
    1. Validates code input
    2. Parses AST using ast.parse()
    3. Traverses AST via CodeSanitizerASTVisitor
    4. Extracts imports and audits them against PyPI API
    5. Converts hallucinated packages into Critical/High findings
    6. Calculates deterministic security score (0-100)
    """
    if not code_str or not code_str.strip():
        return {
            "success": False,
            "error_type": "EMPTY_INPUT",
            "message": "No code provided to analyze. Please paste or upload Python code.",
            "findings": [],
            "packages": [],
            "summary": calculate_security_score([]),
        }

    source_lines = code_str.splitlines()

    # Step 1: AST Parsing
    try:
        tree = ast.parse(code_str)
    except SyntaxError as se:
        return {
            "success": False,
            "error_type": "SYNTAX_ERROR",
            "message": f"SyntaxError at line {se.lineno}, column {se.offset}: {se.msg}",
            "details": {
                "line": se.lineno,
                "offset": se.offset,
                "text": se.text.strip() if se.text else "",
            },
            "findings": [],
            "packages": [],
            "summary": calculate_security_score([]),
        }
    except Exception as ex:
        return {
            "success": False,
            "error_type": "PARSE_ERROR",
            "message": f"Failed to parse AST: {str(ex)}",
            "findings": [],
            "packages": [],
            "summary": calculate_security_score([]),
        }

    # Step 2: AST Traversal
    visitor = CodeSanitizerASTVisitor(source_lines)
    visitor.visit(tree)

    # Step 3: PyPI Package Verification
    packages: List[PackageVerificationResult] = run_package_verification(visitor.imports_map)

    # Step 4: Convert Hallucinated Packages to Vulnerabilities
    all_findings = list(visitor.findings)
    for pkg in packages:
        if pkg.status == "NOT_FOUND":
            line_str = ", ".join(str(l) for l in (pkg.lines or [])) or "N/A"
            first_line = pkg.lines[0] if pkg.lines else 1
            all_findings.append(VulnerabilityFinding(
                rule_id="PACKAGE_HALLUCINATION",
                title=f"AI Package Hallucination: `{pkg.package_name}`",
                severity="HIGH",
                line=first_line,
                code_snippet=f"import {pkg.package_name}  # Line {line_str}",
                explanation=(
                    f"The package `{pkg.package_name}` does not exist on PyPI. "
                    "AI code models frequently hallucinate non-existent libraries with plausible names."
                ),
                why=(
                    "Hallucinated packages create critical supply chain vulnerabilities. Attackers can "
                    "register these hallucinated names on PyPI (Dependency Comb-squatting) to execute malware."
                ),
                recommendation=(
                    f"Remove `{pkg.package_name}`. Verify legitimate library alternatives on PyPI or use "
                    "Python standard library equivalents."
                ),
                vulnerable_example=f"import {pkg.package_name}",
                recommended_example=f"# Replace with verified PyPI package or Python standard library",
            ))

    # Step 5: Deterministic Score Calculation
    summary = calculate_security_score(all_findings)

    return {
        "success": True,
        "error_type": None,
        "message": "Audit completed successfully.",
        "findings": all_findings,
        "packages": packages,
        "summary": summary,
        "code_lines_count": len(source_lines),
    }


if __name__ == "__main__":
    import sys
    import json
    from report import generate_json_report

    args = sys.argv[1:]
    output_json = "--json" in args
    read_stdin = "--stdin" in args
    file_args = [a for a in args if not a.startswith("--")]

    code_to_audit = ""
    target_name = "submitted_code.py"

    if read_stdin:
        code_to_audit = sys.stdin.read()
        target_name = "stdin"
    elif file_args:
        target_file = file_args[0]
        target_name = target_file
        try:
            with open(target_file, "r", encoding="utf-8") as f:
                code_to_audit = f.read()
        except Exception as err:
            print(f"Error reading file: {err}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Usage: python3 analyzer.py <path_to_python_file> [--json] or python3 analyzer.py --stdin [--json]")
        sys.exit(0)

    results = analyze_python_code(code_to_audit)

    if output_json:
        # Convert findings and packages for clean JSON output
        clean_data = {
            "success": results["success"],
            "error_type": results.get("error_type"),
            "message": results.get("message"),
            "summary": results["summary"],
            "findings": [f.to_dict() for f in results["findings"]],
            "packages": [p.to_dict() for p in results["packages"]],
            "code_lines_count": results.get("code_lines_count", 0),
        }
        print(json.dumps(clean_data, indent=2))
    else:
        print(f"\n--- CodeSanitizer Audit Results for: {target_name} ---")
        if not results["success"]:
            print(f"Error: {results['message']}")
        else:
            print(f"Status: {results['summary']['badge']} (Score: {results['summary']['score']}/100)")
            print(f"Findings: {results['summary']['total_findings']} issues detected")
            for finding in results["findings"]:
                print(f"[{finding.severity}] Line {finding.line}: {finding.title}")
            print("\nPackages:")
            for p in results["packages"]:
                print(f" - {p.package_name}: {p.status} ({p.message})")
