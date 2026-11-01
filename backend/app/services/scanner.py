"""Static security analysis engine for Vulnex AI."""

import ast
import re
import uuid
from typing import Any, Dict, List, Optional


class RawFinding:
    def __init__(
        self,
        rule_id: str,
        cwe_id: str,
        title: str,
        severity: str,
        description: str,
        file_path: str,
        line_number: Optional[int] = None,
        code_snippet: Optional[str] = None,
        recommendation: Optional[str] = None
    ):
        self.rule_id = rule_id
        self.cwe_id = cwe_id
        self.title = title
        self.severity = severity
        self.description = description
        self.file_path = file_path
        self.line_number = line_number
        self.code_snippet = code_snippet
        self.recommendation = recommendation


class PythonASTSecurityScanner(ast.NodeVisitor):
    """AST-based static analyzer for Python code. Safe inspection without execution."""

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.file_path = file_path
        self.lines = source_code.splitlines()
        self.findings: List[RawFinding] = []

    def _get_snippet(self, node: ast.AST) -> str:
        lineno = getattr(node, "lineno", 1)
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        snippet = self._get_snippet(node)

        # 1. CWE-95: eval / exec
        if func_name in ("eval", "exec"):
            self.findings.append(
                RawFinding(
                    rule_id="VULN-EVAL-001",
                    cwe_id="CWE-95",
                    title="Direct Dynamic Code Evaluation (eval/exec)",
                    severity="CRITICAL",
                    description=f"Direct invocation of '{func_name}' evaluates arbitrary code and allows arbitrary remote code execution.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    code_snippet=snippet,
                    recommendation="Avoid eval/exec. Use ast.literal_eval for data or safer structured parsers."
                )
            )

        # 2. CWE-78: Command Injection via os.system or subprocess
        if func_name == "system" and isinstance(getattr(node.func, "value", None), ast.Name) and node.func.value.id == "os":
            self.findings.append(
                RawFinding(
                    rule_id="VULN-CMDI-001",
                    cwe_id="CWE-78",
                    title="OS Command Injection via os.system",
                    severity="HIGH",
                    description="os.system executes shell commands directly and is vulnerable to command injection.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                    code_snippet=snippet,
                    recommendation="Use subprocess.run with an argument list and shell=False."
                )
            )

        if func_name in ("Popen", "run", "call", "check_call", "check_output"):
            # Check for shell=True
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(
                        RawFinding(
                            rule_id="VULN-CMDI-002",
                            cwe_id="CWE-78",
                            title="Subprocess Shell=True Execution",
                            severity="HIGH",
                            description="subprocess invoked with shell=True allows command chaining and shell injection.",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            code_snippet=snippet,
                            recommendation="Set shell=False and pass arguments as an explicit array of strings."
                        )
                    )

        # 3. CWE-502: Insecure Deserialization via pickle
        if func_name in ("loads", "load"):
            val = getattr(node.func, "value", None)
            if isinstance(val, ast.Name) and val.id in ("pickle", "_pickle", "cPickle"):
                self.findings.append(
                    RawFinding(
                        rule_id="VULN-DESER-001",
                        cwe_id="CWE-502",
                        title="Insecure Deserialization via pickle",
                        severity="CRITICAL",
                        description="pickle deserialization allows arbitrary object instantiation and remote code execution.",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        code_snippet=snippet,
                        recommendation="Use secure serialization formats like JSON, protocol buffers, or safe schemas."
                    )
                )

        # 4. CWE-502: yaml.load without SafeLoader
        if func_name == "load" and isinstance(getattr(node.func, "value", None), ast.Name) and node.func.value.id == "yaml":
            has_safe_loader = False
            for kw in node.keywords:
                if kw.arg == "Loader" and "SafeLoader" in ast.dump(kw.value):
                    has_safe_loader = True
            if not has_safe_loader:
                self.findings.append(
                    RawFinding(
                        rule_id="VULN-DESER-002",
                        cwe_id="CWE-502",
                        title="Unsafe YAML Deserialization",
                        severity="HIGH",
                        description="yaml.load called without SafeLoader can instantiate arbitrary Python objects.",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        code_snippet=snippet,
                        recommendation="Use yaml.safe_load(...) instead of yaml.load(...)."
                    )
                )

        # 5. CWE-327: Broken Crypto (MD5 / SHA1)
        if func_name in ("md5", "sha1"):
            val = getattr(node.func, "value", None)
            if isinstance(val, ast.Name) and val.id == "hashlib":
                self.findings.append(
                    RawFinding(
                        rule_id="VULN-CRYP-001",
                        cwe_id="CWE-327",
                        title=f"Use of Weak Cryptographic Hash ({func_name.upper()})",
                        severity="MEDIUM",
                        description=f"hashlib.{func_name} is cryptographically broken and vulnerable to collision attacks.",
                        file_path=self.file_path,
                        line_number=node.lineno,
                        code_snippet=snippet,
                        recommendation=f"Use hashlib.sha256 or hashlib.sha3_256 for secure hashing."
                    )
                )

        # 6. CWE-89: SQL Injection via cursor.execute with format / concatenation
        if func_name in ("execute", "executemany"):
            if node.args:
                first_arg = node.args[0]
                is_sqli = False
                # Check JoinedStr (f-string)
                if isinstance(first_arg, ast.JoinedStr):
                    is_sqli = True
                # Check BinOp (modulo % or string addition +)
                elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, (ast.Mod, ast.Add)):
                    is_sqli = True
                # Check .format()
                elif isinstance(first_arg, ast.Call) and isinstance(getattr(first_arg.func, "attr", None), str) and first_arg.func.attr == "format":
                    is_sqli = True

                if is_sqli:
                    self.findings.append(
                        RawFinding(
                            rule_id="VULN-SQLI-001",
                            cwe_id="CWE-89",
                            title="Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
                            severity="CRITICAL",
                            description="SQL query constructed via dynamic string interpolation or concatenation directly inside cursor.execute.",
                            file_path=self.file_path,
                            line_number=node.lineno,
                            code_snippet=snippet,
                            recommendation="Use parameterized queries with database placeholders (e.g., cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)))."
                        )
                    )

        self.generic_visit(node)


class RegexPatternSecurityScanner:
    """Regex and pattern-based scanner for general source code (Python, JS, TS, generic)."""

    def __init__(self, source_code: str, file_path: str):
        self.source_code = source_code
        self.file_path = file_path
        self.lines = source_code.splitlines()

    def scan(self) -> List[RawFinding]:
        findings: List[RawFinding] = []

        patterns = [
            # Hardcoded API keys / Secrets (CWE-798)
            (
                r"(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token|jwt[_-]?secret|password)\s*=\s*['\"][A-Za-z0-9_\-\.]{8,}['\"]",
                "VULN-SECR-001",
                "CWE-798",
                "Hardcoded Credential or Sensitive Token",
                "HIGH",
                "Hardcoded credentials in source code can be extracted from revision history and source repos.",
                "Store secrets in environment variables or a secure secret manager (e.g. AWS Secrets Manager, GCP Secret Manager)."
            ),
            # Path Traversal (CWE-22)
            (
                r"open\(\s*(f['\"].*\{.*\}.*['\"]|['\"].*['\"]\s*\+\s*\w+)",
                "VULN-PATH-001",
                "CWE-22",
                "Unvalidated Path Traversal in File Open",
                "HIGH",
                "Opening files with unvalidated string concatenation allows directory traversal attacks (e.g. ../../etc/passwd).",
                "Use os.path.abspath and os.path.commonpath to verify paths remain within a safe root directory."
            ),
            # SSRF (CWE-918)
            (
                r"(requests\.(get|post|put|delete)|httpx\.(get|post)|urllib\.request\.urlopen)\(\s*(url|target_url|req\.query|request\.args)",
                "VULN-SSRF-001",
                "CWE-918",
                "Server-Side Request Forgery (SSRF)",
                "HIGH",
                "Outbound HTTP request made to unvalidated user-controlled URL allows internal network scanning and cloud metadata access.",
                "Validate URLs against a domain whitelist and enforce strict IP range verification blocking loopback and private ranges."
            ),
            # Insecure CORS (CWE-942)
            (
                r"(allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]\s*,\s*allow_credentials\s*=\s*True|allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\])",
                "VULN-CORS-001",
                "CWE-942",
                "Overly Permissive Cross-Origin Resource Sharing (CORS) Policy",
                "MEDIUM",
                "Wildcard CORS origin with credentials enabled allows arbitrary malicious websites to issue authenticated cross-origin requests.",
                "Explicitly whitelist specific trusted frontend origins instead of using wildcard '*'."
            ),
            # Insecure JS innerHTML / XSS (CWE-79)
            (
                r"\.innerHTML\s*=\s*.*(req\.query|location\.search|\+)",
                "VULN-XSS-001",
                "CWE-79",
                "Client-Side Cross-Site Scripting (XSS) via innerHTML",
                "HIGH",
                "Assigning unsanitized input directly to innerHTML allows execution of malicious JavaScript.",
                "Use textContent, innerText, or DOMPurify.sanitize() to safely render untrusted data."
            )
        ]

        for line_idx, line in enumerate(self.lines, start=1):
            # Skip comments to avoid false positives
            trimmed = line.strip()
            if trimmed.startswith("#") or trimmed.startswith("//") or trimmed.startswith("/*"):
                continue

            for regex, rule_id, cwe_id, title, severity, desc, rec in patterns:
                if re.search(regex, line):
                    findings.append(
                        RawFinding(
                            rule_id=rule_id,
                            cwe_id=cwe_id,
                            title=title,
                            severity=severity,
                            description=desc,
                            file_path=self.file_path,
                            line_number=line_idx,
                            code_snippet=trimmed,
                            recommendation=rec
                        )
                    )

        return findings


class ScannerService:
    """Orchestrates static analysis across Bandit, Semgrep, AST, and pattern scanners."""

    @classmethod
    def scan_code(cls, source_code: str, file_path: str = "snippet.py", language: str = "python") -> List[RawFinding]:
        findings: List[RawFinding] = []
        lang = (language or "python").lower()

        # 1. Bandit Scanner integration for Python
        if lang in ("python", "py") or file_path.endswith(".py"):
            try:
                from app.services.scanners.bandit_scanner import BanditScanner
                bandit = BanditScanner()
                if bandit.is_available():
                    import tempfile
                    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", encoding="utf-8", delete=False) as tf:
                        tf.write(source_code)
                        tf_path = tf.name
                    try:
                        b_res = bandit.scan_file(tf_path, relative_path=file_path)
                        if b_res.success:
                            for bf in b_res.findings:
                                findings.append(
                                    RawFinding(
                                        rule_id=bf.rule_id,
                                        cwe_id=bf.cwe_id or "CWE-UNKNOWN",
                                        title=bf.title,
                                        severity=bf.severity.upper(),
                                        description=bf.description,
                                        file_path=file_path,
                                        line_number=bf.line_start,
                                        code_snippet=bf.evidence,
                                        recommendation=bf.recommendation
                                    )
                                )
                    finally:
                        if os.path.exists(tf_path):
                            os.remove(tf_path)
            except Exception:
                pass

        # 2. AST Scanning for Python
        if lang in ("python", "py") or file_path.endswith(".py"):
            try:
                tree = ast.parse(source_code)
                ast_scanner = PythonASTSecurityScanner(source_code, file_path)
                ast_scanner.visit(tree)
                findings.extend(ast_scanner.findings)
            except SyntaxError:
                pass

        # 3. Regex Pattern Scanning (universal fallback & complement)
        regex_scanner = RegexPatternSecurityScanner(source_code, file_path)
        regex_findings = regex_scanner.scan()

        # Deduplicate findings on (rule_id, file_path, line_number)
        seen = set()
        unique_findings = []
        for f in findings + regex_findings:
            key = (f.rule_id, f.file_path, f.line_number)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings
