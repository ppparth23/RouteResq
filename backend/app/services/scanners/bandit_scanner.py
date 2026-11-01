"""Bandit static security scanner integration for Python."""

import json
import logging
import os
import shutil
import subprocess
import time
from typing import Dict, Optional
from app.services.scanners.base import (
    BaseScanner,
    ScanExecutionResult,
    ScannerFinding,
    redact_secrets
)

logger = logging.getLogger("vulnex.scanner.bandit")

# Known Bandit Test ID to CWE mapping for Bandit rules that don't embed CWE in results
BANDIT_CWE_MAP: Dict[str, str] = {
    "B101": "CWE-703",  # assert_used
    "B102": "CWE-95",   # exec_used
    "B103": "CWE-276",  # set_bad_file_permissions
    "B104": "CWE-200",  # hardcoded_bind_all_interfaces
    "B105": "CWE-798",  # hardcoded_password_string
    "B106": "CWE-798",  # hardcoded_password_funcarg
    "B107": "CWE-798",  # hardcoded_password_default
    "B108": "CWE-377",  # hardcoded_tmp_directory
    "B110": "CWE-703",  # try_except_pass
    "B112": "CWE-703",  # try_except_continue
    "B201": "CWE-601",  # flask_debug_true
    "B301": "CWE-502",  # pickle
    "B302": "CWE-502",  # marshal
    "B303": "CWE-327",  # md5
    "B304": "CWE-327",  # ciphers
    "B305": "CWE-327",  # cipher_modes
    "B306": "CWE-377",  # mktemp_q
    "B307": "CWE-95",   # eval
    "B308": "CWE-79",   # mark_safe
    "B324": "CWE-327",  # hashlib
    "B401": "CWE-311",  # telnet
    "B402": "CWE-319",  # ftplib
    "B501": "CWE-295",  # request_with_no_cert_validation
    "B506": "CWE-502",  # yaml_load
    "B601": "CWE-78",   # paramiko_calls
    "B602": "CWE-78",   # subprocess_popen_with_shell_equals_true
    "B603": "CWE-78",   # subprocess_without_shell_equals_true
    "B604": "CWE-78",   # any_other_function_with_shell_equals_true
    "B605": "CWE-78",   # start_process_with_a_shell
    "B606": "CWE-78",   # start_process_with_no_shell
    "B607": "CWE-78",   # start_process_with_partial_path
    "B608": "CWE-89",   # hardcoded_sql_expressions
    "B609": "CWE-643",  # linux_wildcard_injection
    "B701": "CWE-79",   # jinja2_autoescape_false
    "B702": "CWE-79",   # use_of_mako_templates
    "B703": "CWE-79",   # django_mark_safe
}

BANDIT_CATEGORY_MAP: Dict[str, str] = {
    "CWE-89": "SQL Injection",
    "CWE-78": "Command Injection",
    "CWE-502": "Insecure Deserialization",
    "CWE-798": "Hardcoded Secrets",
    "CWE-327": "Cryptography",
    "CWE-95": "Dynamic Code Evaluation",
    "CWE-79": "Cross-Site Scripting",
    "CWE-295": "Improper Certificate Validation",
    "CWE-377": "Insecure Temporary File",
    "CWE-703": "Error Handling"
}


class BanditScanner(BaseScanner):
    """Integrates OpenSSF Bandit scanner for Python-specific security checks."""

    @property
    def name(self) -> str:
        return "bandit"

    def is_available(self) -> bool:
        return shutil.which("bandit") is not None

    def scan_file(
        self,
        file_path: str,
        relative_path: str,
        timeout_seconds: int = 15
    ) -> ScanExecutionResult:
        start_time = time.time()

        if not self.is_available():
            return ScanExecutionResult(
                scanner_name=self.name,
                success=False,
                error_type="MISSING_EXECUTABLE",
                error_message="Bandit scanner executable ('bandit') not found on system PATH."
            )

        cmd = [
            "bandit",
            "-s", "B404,B603",
            "-f", "json",
            "-q",
            file_path
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                check=False
            )
        except subprocess.TimeoutExpired:
            return ScanExecutionResult(
                scanner_name=self.name,
                success=False,
                error_type="TIMEOUT",
                error_message=f"Bandit scan timed out after {timeout_seconds} seconds.",
                execution_time_ms=(time.time() - start_time) * 1000
            )
        except Exception as e:
            return ScanExecutionResult(
                scanner_name=self.name,
                success=False,
                error_type="INTERNAL_ERROR",
                error_message=f"Failed to execute Bandit: {str(e)}",
                execution_time_ms=(time.time() - start_time) * 1000
            )

        # Parse Bandit output
        raw_stdout = proc.stdout.strip()
        if not raw_stdout:
            # Check stderr for syntax or parse errors
            err_msg = proc.stderr.strip() or "Empty output from Bandit."
            return ScanExecutionResult(
                scanner_name=self.name,
                success=False,
                error_type="MALFORMED_OUTPUT",
                error_message=err_msg,
                execution_time_ms=(time.time() - start_time) * 1000
            )

        try:
            data = json.loads(raw_stdout)
        except json.JSONDecodeError as e:
            return ScanExecutionResult(
                scanner_name=self.name,
                success=False,
                error_type="MALFORMED_OUTPUT",
                error_message=f"Failed to parse Bandit JSON output: {str(e)}",
                execution_time_ms=(time.time() - start_time) * 1000
            )

        results = data.get("results", [])
        findings: List[ScannerFinding] = []

        for item in results:
            test_id = item.get("test_id", "BANDIT-UNKNOWN")
            test_name = item.get("test_name", "")
            raw_severity = (item.get("issue_severity") or "MEDIUM").lower()
            raw_confidence = (item.get("issue_confidence") or "HIGH").lower()

            # Map CWE ID if reliably present
            cwe_id: Optional[str] = None
            issue_cwe = item.get("issue_cwe")
            if isinstance(issue_cwe, dict) and issue_cwe.get("id"):
                cwe_id = f"CWE-{issue_cwe['id']}"
            elif test_id in BANDIT_CWE_MAP:
                cwe_id = BANDIT_CWE_MAP[test_id]

            # Category mapping
            category = BANDIT_CATEGORY_MAP.get(cwe_id, "Python Security") if cwe_id else "Python Security"

            # Line numbers
            line_start = item.get("line_number")
            line_range = item.get("line_range") or []
            line_end = line_range[-1] if line_range else line_start

            # Snippet evidence
            raw_code = item.get("code", "")
            redacted_code = redact_secrets(raw_code.strip())

            # Title
            title = f"{test_id}: {test_name.replace('_', ' ').title()}" if test_name else f"Bandit {test_id}"

            # Severity normalization
            severity = raw_severity
            if severity not in ("critical", "high", "medium", "low", "info", "unknown"):
                severity = "medium"
            if cwe_id in ("CWE-89", "CWE-78", "CWE-502", "CWE-95") and severity == "high":
                severity = "critical"

            confidence = raw_confidence if raw_confidence in ("high", "medium", "low") else "high"

            rec = f"Review Bandit documentation for rule {test_id}: {item.get('more_info', '')}"

            findings.append(
                ScannerFinding(
                    rule_id=test_id,
                    title=title,
                    severity=severity,
                    category=category,
                    cwe_id=cwe_id,
                    file_path=relative_path,
                    line_start=line_start,
                    line_end=line_end,
                    evidence=redacted_code,
                    description=item.get("issue_text", ""),
                    recommendation=rec,
                    source=self.name,
                    confidence=confidence
                )
            )

        return ScanExecutionResult(
            scanner_name=self.name,
            success=True,
            findings=findings,
            execution_time_ms=(time.time() - start_time) * 1000
        )
