"""11-Step Static Security Scanning Pipeline for Vulnex AI."""

from datetime import datetime, timezone
import io
import logging
import os
import shutil
import tempfile
import time
import uuid
import zipfile
from typing import List, Optional, Tuple
from fastapi import HTTPException, status
from app.config import settings
from app.schemas.v1 import Finding, FindingEvidence, ScanResponse, ScanSummary
from app.security.input_validation import sanitize_filename, validate_source_code_size
from app.services.scanners.bandit_scanner import BanditScanner
from app.services.scanners.base import ScanExecutionResult, ScannerFinding
from app.services.scanners.c_cpp_analyzer import CCppSecurityAnalyzer
from app.services.scanners.semgrep_scanner import SemgrepScanner
from app.services.scanners.toolchain import ToolchainDetector
from app.storage.database import save_finding, save_scan

logger = logging.getLogger("vulnex.scanner.pipeline")

SUPPORTED_LANGUAGES = {"python", "py", "c", "cpp", "c++", "h", "hpp"}


class ScanningPipeline:
    """
    Executes the 11-step static security scanning lifecycle:
    1. Validate submitted language
    2. Validate filename
    3. Enforce source-size limits
    4. Store source in controlled temporary workspace
    5. Invoke configured scanners without executing application
    6. Apply timeout
    7. Capture scanner output safely
    8. Parse results
    9. Normalize findings into Finding schema
    10. Store scan summary and findings
    11. Return actual results
    """

    def __init__(
        self,
        enable_bandit: bool = True,
        enable_semgrep: bool = True,
        timeout_seconds: int = 15
    ):
        self.bandit = BanditScanner() if enable_bandit else None
        self.semgrep = SemgrepScanner() if enable_semgrep else None
        self.timeout_seconds = timeout_seconds

    def execute_scan(
        self,
        source_code: str,
        filename: str = "example.py",
        language: str = "python",
        scan_id: Optional[str] = None,
        target_platform: Optional[str] = "generic",
        rtos: Optional[str] = None,
        compiler: Optional[str] = None
    ) -> Tuple[ScanResponse, List[Finding]]:
        start_time = time.time()
        scan_id = scan_id or f"scan_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        # Step 1: Validate the submitted language
        lang = (language or "python").lower().strip()
        if lang not in SUPPORTED_LANGUAGES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported language '{language}'. Currently configured language scanner supports: {list(SUPPORTED_LANGUAGES)}."
            )

        is_c_cpp = lang in ("c", "cpp", "c++", "h", "hpp")
        default_file = "main.c" if lang in ("c", "h") else "main.cpp" if is_c_cpp else "example.py"

        # Step 2: Validate the filename
        clean_filename = sanitize_filename(filename or default_file)
        if not is_c_cpp and not clean_filename.endswith(".py"):
            clean_filename += ".py"
        elif is_c_cpp and not clean_filename.endswith((".c", ".cpp", ".cc", ".cxx", ".h", ".hpp")):
            clean_filename += ".c" if lang in ("c", "h") else ".cpp"

        # Step 3: Enforce source-size limits
        validate_source_code_size(source_code)

        # Step 4: Store source in a controlled temporary workspace
        temp_dir = tempfile.mkdtemp(prefix="vulnex_scan_ws_")
        target_file_path = os.path.join(temp_dir, clean_filename)

        with open(target_file_path, "w", encoding="utf-8") as f:
            f.write(source_code)

        scanner_results: List[ScanExecutionResult] = []
        tool_status = ToolchainDetector.get_tool_status()

        try:
            # Step 5 & 6 & 7 & 8: Invoke configured scanners with timeouts and safe output capture
            if not is_c_cpp:
                # 5a. Bandit (Python only)
                if self.bandit and self.bandit.is_available():
                    b_res = self.bandit.scan_file(
                        file_path=target_file_path,
                        relative_path=clean_filename,
                        timeout_seconds=self.timeout_seconds
                    )
                    scanner_results.append(b_res)
                    if not b_res.success:
                        logger.warning(f"Bandit scanner execution notice: {b_res.error_type} - {b_res.error_message}")

                # 5b. Semgrep (Python)
                if self.semgrep and self.semgrep.is_available():
                    s_res = self.semgrep.scan_file(
                        file_path=target_file_path,
                        relative_path=clean_filename,
                        timeout_seconds=self.timeout_seconds,
                        language="python"
                    )
                    scanner_results.append(s_res)
                    if not s_res.success:
                        logger.warning(f"Semgrep scanner execution notice: {s_res.error_type} - {s_res.error_message}")

                # 5c. Python AST & Regex Pattern Analysis
                try:
                    from app.services.scanner import ScannerService
                    ast_findings = ScannerService.scan_code(source_code, clean_filename, language)
                    if ast_findings:
                        converted = [
                            ScannerFinding(
                                rule_id=af.rule_id,
                                title=af.title,
                                severity=af.severity,
                                category="Security Flaw",
                                cwe_id=af.cwe_id,
                                file_path=clean_filename,
                                line_start=af.line_number or 1,
                                line_end=af.line_number or 1,
                                evidence=af.code_snippet or "",
                                description=af.description,
                                recommendation=af.recommendation,
                                source="ast_scanner" if af.rule_id.startswith("VULN-") else "scanner",
                                confidence="high"
                            )
                            for af in ast_findings
                        ]
                        scanner_results.append(ScanExecutionResult(
                            scanner_name="ast_scanner",
                            success=True,
                            findings=converted
                        ))
                except Exception as e:
                    logger.warning(f"Python AST/Regex scanner execution error: {e}")
            else:
                # C / C++ & Embedded IoT Analysis
                # 5a. Semgrep (C/C++)
                if self.semgrep and self.semgrep.is_available():
                    s_res = self.semgrep.scan_file(
                        file_path=target_file_path,
                        relative_path=clean_filename,
                        timeout_seconds=self.timeout_seconds,
                        language="c"
                    )
                    scanner_results.append(s_res)
                    if not s_res.success:
                        logger.warning(f"Semgrep C/C++ scanner notice: {s_res.error_type} - {s_res.error_message}")

                # 5b. Custom C/C++ AST & Semantic Flow Security Analyzer
                try:
                    c_findings = CCppSecurityAnalyzer.scan_code(
                        source_code=source_code,
                        filename=clean_filename,
                        target_platform=target_platform
                    )
                    if c_findings:
                        converted = [
                            ScannerFinding(
                                rule_id=cf.rule_id,
                                title=cf.title,
                                severity=cf.severity,
                                category=cf.category,
                                cwe_id=cf.cwe_id,
                                file_path=clean_filename,
                                line_start=cf.line_start,
                                line_end=cf.line_end,
                                evidence=cf.code_snippet,
                                description=cf.description,
                                recommendation=cf.recommendation,
                                source=cf.source,
                                confidence=cf.confidence,
                                cvss_score=cf.cvss_score,
                                cvss_version=cf.cvss_version,
                                function_name=cf.function_name,
                                column_number=cf.column_number,
                                root_cause=cf.root_cause,
                                exploitation_conditions=cf.exploitation_conditions
                            )
                            for cf in c_findings
                        ]
                        scanner_results.append(ScanExecutionResult(
                            scanner_name="c_cpp_analyzer",
                            success=True,
                            findings=converted
                        ))
                except Exception as e:
                    logger.warning(f"C/C++ AST analyzer error: {e}")

            # If no external scanner could execute successfully, check why
            successful_runs = [r for r in scanner_results if r.success]
            if not successful_runs and scanner_results:
                # All configured scanners failed
                primary_err = scanner_results[0]
                error_msg = f"Scanner failed ({primary_err.error_type}): {primary_err.error_message}"
                failed_record = {
                    "id": scan_id,
                    "source_type": "source_code",
                    "target_name": clean_filename,
                    "status": "failed",
                    "language": language,
                    "summary": ScanSummary().model_dump(),
                    "source_code": source_code,
                    "created_at": now_iso,
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "error_message": error_msg
                }
                save_scan(failed_record)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=error_msg
                )

            # Step 9: Normalize findings into the API's Finding schema
            normalized_findings, summary = self._normalize_findings(scanner_results, scan_id)

            # Step 10: Store scan summary and findings
            completed_iso = datetime.now(timezone.utc).isoformat()
            duration_ms = round((time.time() - start_time) * 1000, 2)
            loc = len(source_code.splitlines()) if source_code else 0
            density = round((len(normalized_findings) / max(1, loc)) * 100, 2)

            scan_record = {
                "id": scan_id,
                "source_type": "source_code",
                "target_name": clean_filename,
                "status": "completed",
                "language": language,
                "summary": summary.model_dump(),
                "source_code": source_code,
                "created_at": now_iso,
                "completed_at": completed_iso,
                "lines_of_code": loc,
                "duration_ms": duration_ms,
                "files_count": 1,
                "vulnerability_density": density,
                "target_platform": target_platform,
                "rtos": rtos,
                "compiler": compiler,
                "tool_status": tool_status,
                "error_message": None
            }
            save_scan(scan_record)

            for finding in normalized_findings:
                save_finding(finding.model_dump())

            # Step 11: Return actual results
            response = ScanResponse(
                id=scan_id,
                source_type="source_code",
                target_name=clean_filename,
                status="completed",
                language=language,
                summary=summary,
                findings=normalized_findings,
                created_at=now_iso,
                completed_at=completed_iso,
                lines_of_code=loc,
                duration_ms=duration_ms,
                files_count=1,
                vulnerability_density=density,
                target_platform=target_platform,
                rtos=rtos,
                compiler=compiler,
                tool_status=tool_status,
                error_message=None
            )

            return response, normalized_findings

        finally:
            # Ephemeral cleanup of controlled temporary workspace
            shutil.rmtree(temp_dir, ignore_errors=True)

    def execute_scan_zip(
        self,
        zip_bytes: bytes,
        zip_filename: str = "project.zip",
        scan_id: Optional[str] = None,
        target_platform: Optional[str] = "generic"
    ) -> Tuple[ScanResponse, List[Finding]]:
        start_time = time.time()
        scan_id = scan_id or f"scan_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        # Enforce zip size limit (max 20MB)
        max_zip_size = 20 * 1024 * 1024
        if len(zip_bytes) > max_zip_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Zip archive exceeds maximum allowed size of 20 MB."
            )

        clean_zip_name = sanitize_filename(zip_filename)
        temp_dir = tempfile.mkdtemp(prefix="vulnex_zip_ws_")
        tool_status = ToolchainDetector.get_tool_status()

        try:
            try:
                with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                    # Security: check for zip bombs and path traversal
                    total_uncompressed = 0
                    max_uncompressed = 50 * 1024 * 1024
                    real_temp_dir = os.path.realpath(temp_dir)

                    for info in zf.infolist():
                        total_uncompressed += info.file_size
                        if total_uncompressed > max_uncompressed:
                            raise HTTPException(
                                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                detail="Uncompressed zip contents exceed 50 MB limit."
                            )
                        # Path traversal check
                        dest_path = os.path.realpath(os.path.join(temp_dir, info.filename))
                        if not (dest_path == real_temp_dir or dest_path.startswith(real_temp_dir + os.sep)):
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Zip archive contains path traversal entry: {info.filename}"
                            )

                    zf.extractall(temp_dir)
            except zipfile.BadZipFile:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Submitted file is not a valid or readable ZIP archive."
                )

            # Discover Python and C/C++ source files
            py_files: List[Tuple[str, str]] = []  # (abs_path, relative_path)
            c_files: List[Tuple[str, str]] = []
            total_loc = 0

            for root, _, files in os.walk(temp_dir):
                for f in files:
                    f_lower = f.lower()
                    abs_p = os.path.join(root, f)
                    rel_p = os.path.relpath(abs_p, temp_dir).replace("\\", "/")

                    if f_lower.endswith(".py"):
                        py_files.append((abs_p, rel_p))
                        try:
                            with open(abs_p, "r", encoding="utf-8", errors="ignore") as pf:
                                total_loc += len(pf.readlines())
                        except Exception:
                            pass
                    elif f_lower.endswith((".c", ".cpp", ".cc", ".cxx", ".h", ".hpp")):
                        c_files.append((abs_p, rel_p))
                        try:
                            with open(abs_p, "r", encoding="utf-8", errors="ignore") as pf:
                                total_loc += len(pf.readlines())
                        except Exception:
                            pass

            scanner_results: List[ScanExecutionResult] = []

            # 1. Python Scanners
            if py_files:
                if self.bandit and self.bandit.is_available():
                    b_res = self.bandit.scan_file(
                        file_path=temp_dir,
                        relative_path=clean_zip_name,
                        timeout_seconds=self.timeout_seconds * 2
                    )
                    scanner_results.append(b_res)

                if self.semgrep and self.semgrep.is_available():
                    s_res = self.semgrep.scan_file(
                        file_path=temp_dir,
                        relative_path=clean_zip_name,
                        timeout_seconds=self.timeout_seconds * 2,
                        language="python"
                    )
                    scanner_results.append(s_res)

                try:
                    from app.services.scanner import ScannerService
                    for abs_p, rel_p in py_files:
                        try:
                            with open(abs_p, "r", encoding="utf-8", errors="ignore") as pf:
                                content = pf.read()
                            ast_findings = ScannerService.scan_code(content, rel_p, "python")
                            if ast_findings:
                                converted = [
                                    ScannerFinding(
                                        rule_id=af.rule_id,
                                        title=af.title,
                                        severity=af.severity,
                                        category="Security Flaw",
                                        cwe_id=af.cwe_id,
                                        file_path=rel_p,
                                        line_start=af.line_number or 1,
                                        line_end=af.line_number or 1,
                                        evidence=af.code_snippet or "",
                                        description=af.description,
                                        recommendation=af.recommendation,
                                        source="ast_scanner" if af.rule_id.startswith("VULN-") else "scanner",
                                        confidence="high"
                                    )
                                    for af in ast_findings
                                ]
                                scanner_results.append(ScanExecutionResult(
                                    scanner_name="ast_scanner",
                                    success=True,
                                    findings=converted
                                ))
                        except Exception:
                            pass
                except Exception as e:
                    logger.warning(f"Python AST scanning on zip failed: {e}")

            # 2. C/C++ Scanners
            if c_files:
                if self.semgrep and self.semgrep.is_available():
                    s_c_res = self.semgrep.scan_file(
                        file_path=temp_dir,
                        relative_path=clean_zip_name,
                        timeout_seconds=self.timeout_seconds * 2,
                        language="c"
                    )
                    scanner_results.append(s_c_res)

                for abs_p, rel_p in c_files:
                    try:
                        with open(abs_p, "r", encoding="utf-8", errors="ignore") as pf:
                            c_content = pf.read()
                        c_findings = CCppSecurityAnalyzer.scan_code(
                            source_code=c_content,
                            filename=rel_p,
                            target_platform=target_platform
                        )
                        if c_findings:
                            converted = [
                                ScannerFinding(
                                    rule_id=cf.rule_id,
                                    title=cf.title,
                                    severity=cf.severity,
                                    category=cf.category,
                                    cwe_id=cf.cwe_id,
                                    file_path=rel_p,
                                    line_start=cf.line_start,
                                    line_end=cf.line_end,
                                    evidence=cf.code_snippet,
                                    description=cf.description,
                                    recommendation=cf.recommendation,
                                    source=cf.source,
                                    confidence=cf.confidence,
                                    cvss_score=cf.cvss_score,
                                    cvss_version=cf.cvss_version,
                                    function_name=cf.function_name,
                                    column_number=cf.column_number,
                                    root_cause=cf.root_cause,
                                    exploitation_conditions=cf.exploitation_conditions
                                )
                                for cf in c_findings
                            ]
                            scanner_results.append(ScanExecutionResult(
                                scanner_name="c_cpp_analyzer",
                                success=True,
                                findings=converted
                            ))
                    except Exception as e:
                        logger.warning(f"C/C++ AST file scanning failed on {rel_p}: {e}")

            normalized_findings, summary = self._normalize_findings(scanner_results, scan_id)

            completed_iso = datetime.now(timezone.utc).isoformat()
            duration_ms = round((time.time() - start_time) * 1000, 2)
            density = round((len(normalized_findings) / max(1, total_loc)) * 100, 2)
            total_files = len(py_files) + len(c_files)

            detected_lang = "c/cpp" if (c_files and not py_files) else ("python" if (py_files and not c_files) else "multi-language")

            scan_record = {
                "id": scan_id,
                "source_type": "zip_archive",
                "target_name": clean_zip_name,
                "status": "completed",
                "language": detected_lang,
                "summary": summary.model_dump(),
                "source_code": f"# ZIP Archive: {clean_zip_name} ({total_files} source files: {len(c_files)} C/C++, {len(py_files)} Python, {total_loc} LOC)",
                "created_at": now_iso,
                "completed_at": completed_iso,
                "lines_of_code": total_loc,
                "duration_ms": duration_ms,
                "files_count": total_files,
                "vulnerability_density": density,
                "target_platform": target_platform,
                "tool_status": tool_status,
                "error_message": None
            }
            save_scan(scan_record)

            for finding in normalized_findings:
                save_finding(finding.model_dump())

            response = ScanResponse(
                id=scan_id,
                source_type="zip_archive",
                target_name=clean_zip_name,
                status="completed",
                language=detected_lang,
                summary=summary,
                findings=normalized_findings,
                created_at=now_iso,
                completed_at=completed_iso,
                lines_of_code=total_loc,
                duration_ms=duration_ms,
                files_count=total_files,
                vulnerability_density=density,
                target_platform=target_platform,
                tool_status=tool_status,
                error_message=None
            )

            return response, normalized_findings

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _normalize_findings(
        self,
        scanner_results: List[ScanExecutionResult],
        scan_id: str
    ) -> Tuple[List[Finding], ScanSummary]:
        raw_list: List[ScannerFinding] = []
        for res in scanner_results:
            if res.success:
                raw_list.extend(res.findings)

        # Deduplicate findings on (cwe_id, line_start) while preserving original rule IDs
        seen = set()
        normalized: List[Finding] = []
        summary = ScanSummary()

        for rf in raw_list:
            dedup_key = (rf.cwe_id or rf.rule_id, rf.line_start)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            finding_id = f"find_{uuid.uuid4().hex[:12]}"
            sev = rf.severity.lower()
            if sev not in ("critical", "high", "medium", "low", "info", "unknown"):
                sev = "medium"

            summary.total += 1
            if sev == "critical":
                summary.critical += 1
            elif sev == "high":
                summary.high += 1
            elif sev == "medium":
                summary.medium += 1
            elif sev == "low":
                summary.low += 1
            elif sev == "info":
                summary.info += 1
            else:
                summary.unknown += 1

            evidence = FindingEvidence(
                snippet=rf.evidence,
                ast_rule=rf.rule_id,
                pattern=rf.rule_id
            )

            cvss_score = rf.cvss_score
            if cvss_score is None:
                cvss_map = {
                    "critical": 9.8,
                    "high": 8.5,
                    "medium": 6.5,
                    "low": 3.8,
                    "info": 0.0,
                    "unknown": 5.0
                }
                cvss_score = cvss_map.get(sev, 6.0)

            f = Finding(
                id=finding_id,
                scan_id=scan_id,
                rule_id=rf.rule_id,
                title=rf.title,
                severity=sev,
                category=rf.category,
                cwe_id=rf.cwe_id or "CWE-UNKNOWN",
                file_path=rf.file_path,
                line_start=rf.line_start,
                line_end=rf.line_end,
                line_number=rf.line_start,
                code_snippet=rf.evidence,
                evidence=evidence,
                description=rf.description,
                impact=rf.description if "Potential impact" not in rf.description else "Potential violation of security best practices.",
                recommendation=rf.recommendation or "Review code against safe implementation patterns.",
                source=rf.source,
                confidence=rf.confidence,
                cvss_score=cvss_score,
                cvss_version=getattr(rf, "cvss_version", "3.1"),
                function_name=getattr(rf, "function_name", None),
                column_number=getattr(rf, "column_number", None),
                root_cause=getattr(rf, "root_cause", None),
                exploitation_conditions=getattr(rf, "exploitation_conditions", None),
                status="open"
            )
            normalized.append(f)

        return normalized, summary
