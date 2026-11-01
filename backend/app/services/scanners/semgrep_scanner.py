"""Semgrep static security scanner integration for Python."""

import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import time
from typing import List, Optional
from app.services.scanners.base import (
    BaseScanner,
    ScanExecutionResult,
    ScannerFinding,
    redact_secrets
)

logger = logging.getLogger("vulnex.scanner.semgrep")

DEFAULT_PYTHON_RULE_FILE = Path(__file__).resolve().parent / "rules" / "semgrep_python_security.yaml"
DEFAULT_C_CPP_RULE_FILE = Path(__file__).resolve().parent / "rules" / "semgrep_c_cpp_security.yaml"


class SemgrepScanner(BaseScanner):
    """Integrates Semgrep scanner with curated Python and C/C++ security rule packs."""

    def __init__(self, rule_pack_path: Optional[str] = None, language: str = "python"):
        self.language = (language or "python").lower().strip()
        if rule_pack_path:
            self.rule_pack_path = rule_pack_path
        elif self.language in ("c", "cpp", "c++", "h", "hpp"):
            self.rule_pack_path = str(DEFAULT_C_CPP_RULE_FILE)
        else:
            self.rule_pack_path = str(DEFAULT_PYTHON_RULE_FILE)

    @property
    def name(self) -> str:
        return "semgrep"

    def is_available(self) -> bool:
        return shutil.which("semgrep") is not None and os.path.exists(self.rule_pack_path)

    def scan_file(
        self,
        file_path: str,
        relative_path: str,
        timeout_seconds: int = 45,
        language: Optional[str] = None
    ) -> ScanExecutionResult:
        start_time = time.time()

        active_rule_pack = self.rule_pack_path
        lang = (language or self.language).lower().strip()
        if lang in ("c", "cpp", "c++", "h", "hpp"):
            active_rule_pack = str(DEFAULT_C_CPP_RULE_FILE)
        elif lang in ("python", "py"):
            active_rule_pack = str(DEFAULT_PYTHON_RULE_FILE)

        if not (shutil.which("semgrep") is not None and os.path.exists(active_rule_pack)):
            return ScanExecutionResult(
                scanner_name=self.name,
                success=False,
                error_type="MISSING_EXECUTABLE",
                error_message=f"Semgrep scanner executable or rule pack ({active_rule_pack}) not configured/installed."
            )

        cmd = [
            "semgrep",
            "scan",
            "--json",
            "--quiet",
            "--config", active_rule_pack,
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
                error_message=f"Semgrep scan timed out after {timeout_seconds} seconds.",
                execution_time_ms=(time.time() - start_time) * 1000
            )
        except Exception as e:
            return ScanExecutionResult(
                scanner_name=self.name,
                success=False,
                error_type="INTERNAL_ERROR",
                error_message=f"Failed to execute Semgrep: {str(e)}",
                execution_time_ms=(time.time() - start_time) * 1000
            )

        raw_stdout = proc.stdout.strip()
        if not raw_stdout:
            err_msg = proc.stderr.strip() or "Empty output from Semgrep."
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
                error_message=f"Failed to parse Semgrep JSON output: {str(e)}",
                execution_time_ms=(time.time() - start_time) * 1000
            )

        results = data.get("results", [])
        findings: List[ScannerFinding] = []

        for item in results:
            check_id = item.get("check_id", "SEMGREP-RULE")
            # Clean check_id prefix if temporary file path was prepended
            display_rule_id = check_id.split(".")[-1] if "." in check_id else check_id

            extra = item.get("extra", {})
            metadata = extra.get("metadata", {})
            cwe_id = metadata.get("cwe")
            category = metadata.get("category", "Semgrep Security")
            recommendation = metadata.get("recommendation", "Review secure coding guidelines for this rule.")

            raw_severity = (extra.get("severity") or "WARNING").upper()
            if raw_severity == "ERROR":
                severity = "critical" if cwe_id in ("CWE-89", "CWE-78", "CWE-502", "CWE-95") else "high"
            elif raw_severity == "WARNING":
                severity = "medium"
            else:
                severity = "low"

            start_loc = item.get("start", {})
            end_loc = item.get("end", {})
            line_start = start_loc.get("line")
            line_end = end_loc.get("line") or line_start

            raw_lines = extra.get("lines", "")
            redacted_code = redact_secrets(raw_lines.strip())

            title = f"{display_rule_id.replace('-', ' ').title()}"

            findings.append(
                ScannerFinding(
                    rule_id=check_id,
                    title=title,
                    severity=severity,
                    category=category,
                    cwe_id=cwe_id,
                    file_path=relative_path,
                    line_start=line_start,
                    line_end=line_end,
                    evidence=redacted_code,
                    description=extra.get("message", ""),
                    recommendation=recommendation,
                    source=self.name,
                    confidence="high"
                )
            )

        return ScanExecutionResult(
            scanner_name=self.name,
            success=True,
            findings=findings,
            execution_time_ms=(time.time() - start_time) * 1000
        )
