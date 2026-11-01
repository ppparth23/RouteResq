"""Typed Pydantic schemas for the Vulnex AI v1 REST API Contract."""

from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator

# Severity types
SeverityLevel = Literal["critical", "high", "medium", "low", "info", "unknown"]

# Lifecycle state types
ScanStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
TaskStatus = Literal["queued", "running", "completed", "failed", "requires_review", "validation_unavailable"]


# ============================================================================
# 1. Evidence and Findings
# ============================================================================

class FindingEvidence(BaseModel):
    snippet: Optional[str] = Field(None, description="Exact code snippet where vulnerability was found")
    context: Optional[str] = Field(None, description="Surrounding code lines for context")
    ast_rule: Optional[str] = Field(None, description="AST rule identifier")
    pattern: Optional[str] = Field(None, description="Matched regex or rule pattern")

    model_config = ConfigDict(from_attributes=True)


class Finding(BaseModel):
    id: str = Field(..., description="Unique finding ID")
    scan_id: str = Field(..., description="Scan ID associated with finding")
    rule_id: Optional[str] = Field(None, description="Rule identifier")
    title: str = Field(..., description="Vulnerability title")
    severity: SeverityLevel = Field(..., description="Vulnerability severity level")
    category: str = Field(default="Security", description="Category of finding (e.g. Injection, Secrets, Cryptography)")
    cwe_id: str = Field(..., description="CWE identifier (e.g. CWE-89)")
    file_path: str = Field(..., description="File path relative to scanned target")
    line_start: Optional[int] = Field(None, description="Starting line number")
    line_end: Optional[int] = Field(None, description="Ending line number")
    line_number: Optional[int] = Field(None, description="Alias for starting line number")
    code_snippet: Optional[str] = Field(None, description="Alias for extracted snippet")
    evidence: Optional[FindingEvidence] = Field(None, description="Structured evidence details")
    description: str = Field(..., description="Detailed description of vulnerability")
    impact: Optional[str] = Field(None, description="Potential impact if exploited")
    recommendation: Optional[str] = Field(None, description="Remediation recommendation")
    source: str = Field(default="ast_scanner", description="Detection source (ast_scanner, regex_scanner)")
    confidence: Literal["high", "medium", "low"] = Field(default="high", description="Detection confidence")
    cvss_score: Optional[float] = Field(None, description="CVSS 3.1 base score")
    cvss_version: Optional[str] = Field("3.1", description="CVSS version")
    function_name: Optional[str] = Field(None, description="Enclosing C/C++/Python function name")
    column_number: Optional[int] = Field(1, description="Exact column number")
    root_cause: Optional[str] = Field(None, description="Underlying root cause analysis")
    exploitation_conditions: Optional[str] = Field(None, description="Conditions required for exploitability")
    status: str = Field(default="open", description="Finding lifecycle status (open, in_remediation, resolved)")

    model_config = ConfigDict(from_attributes=True)

    def model_post_init(self, __context: Any) -> None:
        if self.line_number is None and self.line_start is not None:
            self.line_number = self.line_start
        elif self.line_start is None and self.line_number is not None:
            self.line_start = self.line_number
        if self.code_snippet is None and self.evidence and self.evidence.snippet:
            self.code_snippet = self.evidence.snippet


# ============================================================================
# 2. Scans
# ============================================================================

class SourceCodeScanRequest(BaseModel):
    source_type: Literal["source_code"] = "source_code"
    language: str = Field(default="python", description="Language of source code (python, c, cpp, etc.)")
    filename: str = Field(default="example.py", description="Virtual filename for target")
    source_code: str = Field(..., min_length=1, description="Source code text to scan")
    target_platform: Optional[str] = Field(default="generic", description="Target microcontroller/platform: generic, esp32, stm32, freertos, zephyr, arduino, rp2040")
    rtos: Optional[str] = Field(default=None, description="Optional RTOS environment: freertos, zephyr, none")
    compiler: Optional[str] = Field(default="gcc", description="Compiler toolchain: gcc, clang, arm-none-eabi-gcc")

    @field_validator("filename")
    @classmethod
    def validate_filename_no_traversal(cls, v: str) -> str:
        if ".." in v or "/" in v or "\\" in v:
            import os
            return os.path.basename(v.replace("\\", "/")) or "example.py"
        return v


class RepositoryScanRequest(BaseModel):
    source_type: Literal["repository"] = "repository"
    repo_url: str = Field(..., description="Authorized git repository HTTPS URL")
    branch: Optional[str] = Field(default="main", description="Git branch to scan")
    auth_token: Optional[str] = Field(default=None, description="Optional bearer / personal access token")


ScanRequest = Union[SourceCodeScanRequest, RepositoryScanRequest]


class ScanSummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    unknown: int = 0
    total_findings: Optional[int] = None
    critical_count: Optional[int] = None
    high_count: Optional[int] = None
    medium_count: Optional[int] = None
    low_count: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)

    def model_post_init(self, __context: Any) -> None:
        if self.total_findings is None:
            self.total_findings = self.total
        elif self.total == 0 and self.total_findings > 0:
            self.total = self.total_findings
        if self.critical_count is None:
            self.critical_count = self.critical
        if self.high_count is None:
            self.high_count = self.high
        if self.medium_count is None:
            self.medium_count = self.medium
        if self.low_count is None:
            self.low_count = self.low


class ScanResponse(BaseModel):
    id: str = Field(..., description="Unique scan ID")
    source_type: str = Field(default="source_code", description="Target source type: source_code or repository")
    target_type: Optional[str] = Field(default=None, description="Compatibility alias for source_type")
    target_name: str = Field(..., description="Target filename or repository URL")
    status: ScanStatus = Field(..., description="Current scan lifecycle state")
    language: Optional[str] = Field(None, description="Language scanned")
    summary: Optional[ScanSummary] = Field(default_factory=ScanSummary, description="Summary counts by severity")
    findings: Optional[List[Finding]] = Field(default=None, description="List of findings if included in response")
    lines_of_code: Optional[int] = Field(default=0, description="Total lines of code analyzed")
    duration_ms: Optional[float] = Field(default=0.0, description="Total scan duration in milliseconds")
    files_count: Optional[int] = Field(default=1, description="Total files analyzed")
    vulnerability_density: Optional[float] = Field(default=0.0, description="Flaws per 100 LOC")
    target_platform: Optional[str] = Field(default="generic", description="Target platform/architecture")
    rtos: Optional[str] = Field(default=None, description="Target RTOS if applicable")
    tool_status: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Compiler and scanner toolchain status")
    created_at: str = Field(..., description="ISO 8601 creation timestamp")
    completed_at: Optional[str] = Field(None, description="ISO 8601 completion timestamp")
    error_message: Optional[str] = Field(None, description="Error message if scan failed")

    model_config = ConfigDict(from_attributes=True)

    def model_post_init(self, __context: Any) -> None:
        if self.target_type is None:
            self.target_type = self.source_type
        if self.source_type is None and self.target_type is not None:
            self.source_type = self.target_type


class PaginatedScanHistory(BaseModel):
    items: List[ScanResponse] = Field(..., description="List of scans")
    total: int = Field(..., description="Total scan count")
    page: int = Field(..., description="Current page number (1-based)")
    limit: int = Field(..., description="Page size limit")
    pages: int = Field(..., description="Total pages")

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# 3. Remediation & Diff
# ============================================================================

class RemediationRequest(BaseModel):
    prompt_context: Optional[str] = Field(None, description="Optional context or instructions for remediation")
    auto_validate: bool = Field(default=False, description="Whether to automatically trigger patch validation")


class RemediationResponse(BaseModel):
    id: str = Field(..., description="Unique remediation ID")
    finding_id: str = Field(..., description="Associated finding ID")
    scan_id: str = Field(..., description="Associated scan ID")
    status: TaskStatus = Field(..., description="Remediation lifecycle state")
    summary: Optional[str] = Field(None, description="Executive summary of patch")
    explanation: Optional[str] = Field(None, description="Explanation of proposed repair")
    limitations: List[str] = Field(default_factory=list, description="Known limitations or assumptions")
    original_hash: Optional[str] = Field(None, description="SHA-256 hash of original code")
    proposed_hash: Optional[str] = Field(None, description="SHA-256 hash of proposed code")
    provider: Optional[str] = Field(None, description="AI provider used for remediation")
    model: Optional[str] = Field(None, description="AI model used for remediation")
    validation_status: str = Field(default="UNVALIDATED", description="Validation status (e.g. UNVALIDATED, VALIDATED)")
    requires_review: bool = Field(default=True, description="Whether review is required before merging")
    artifact_path: Optional[str] = Field(None, description="Relative path to stored patch artifact directory")
    added_lines: Optional[int] = Field(0, description="Count of added lines (+)")
    removed_lines: Optional[int] = Field(0, description="Count of removed lines (-)")
    created_at: str = Field(..., description="ISO 8601 creation timestamp")
    updated_at: Optional[str] = Field(None, description="ISO 8601 updated timestamp")
    error_message: Optional[str] = Field(None, description="Error message if remediation failed")

    model_config = ConfigDict(from_attributes=True)


class CodeDiff(BaseModel):
    remediation_id: str = Field(..., description="Associated remediation ID")
    finding_id: str = Field(..., description="Associated finding ID")
    file_path: str = Field(..., description="File being modified")
    original_code: str = Field(..., description="Original vulnerable code")
    proposed_code: str = Field(..., description="Remediated secure code")
    unified_diff: str = Field(..., description="Unified diff (a/ -> b/)")
    changes_count: Optional[int] = Field(None, description="Number of modified lines")
    added_lines: Optional[int] = Field(0, description="Count of added lines (+)")
    removed_lines: Optional[int] = Field(0, description="Count of removed lines (-)")
    original_hash: Optional[str] = Field(None, description="SHA-256 hash of original code")
    proposed_hash: Optional[str] = Field(None, description="SHA-256 hash of proposed code")
    summary: Optional[str] = Field(None, description="Summary of repair")
    explanation: Optional[str] = Field(None, description="Detailed explanation/rationale")
    limitations: List[str] = Field(default_factory=list, description="Known limitations or assumptions")
    validation_status: Optional[str] = Field("UNVALIDATED", description="Validation status")
    requires_review: bool = Field(True, description="Whether review is required before merging")

    model_config = ConfigDict(from_attributes=True)


class CombinedRemediationResponse(BaseModel):
    scan_id: str = Field(..., description="Scan ID")
    target_name: str = Field(..., description="Target file name")
    original_code: str = Field(..., description="Original submitted source code")
    remediated_code: str = Field(..., description="Complete combined source code with all vulnerabilities corrected")
    unified_diff: str = Field(..., description="Full file unified diff")
    added_lines: Optional[int] = Field(0, description="Added lines count")
    removed_lines: Optional[int] = Field(0, description="Removed lines count")
    total_findings: int = Field(..., description="Total vulnerabilities detected in file")
    total_fixes: int = Field(..., description="Total vulnerabilities remediated in file")
    fixes_applied: List[Dict[str, Any]] = Field(default_factory=list, description="List of all fixes applied")
    all_vulnerabilities_fixed: bool = Field(default=True, description="Whether all vulnerabilities are resolved")

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# 4. Validation
# ============================================================================

class ValidationCheck(BaseModel):
    name: str = Field(..., description="Check name: source_parsing, patch_generation, patch_application, compilation, static_security_analysis, dynamic_tests, regression_tests, firmware_build")
    status: Literal["passed", "failed", "error", "not_available", "blocked", "not_run"] = Field(..., description="Check outcome")
    details: str = Field(..., description="Sanitized diagnostic details and exit code or reason")
    exit_code: Optional[int] = Field(None, description="Process exit code if executed")
    duration_ms: Optional[float] = Field(None, description="Check duration in milliseconds")

    model_config = ConfigDict(from_attributes=True)


class ValidationRequest(BaseModel):
    strict_mode: bool = Field(default=True, description="Strict mode enforces zero introduced findings")
    trusted_test_command: Optional[str] = Field(default=None, description="Optional trusted test command to run in container sandbox")


class ValidationResult(BaseModel):
    id: str = Field(..., description="Unique validation job ID")
    validation_id: Optional[str] = Field(None, description="Alias for id")
    remediation_id: str = Field(..., description="Associated remediation ID")
    status: TaskStatus = Field(..., description="Validation lifecycle state")
    is_valid: bool = Field(..., description="Whether patch passed all security and syntax criteria")
    syntax_valid: bool = Field(..., description="Whether patched code parses without syntax errors")
    target_vulnerability_eradicated: bool = Field(..., description="Whether the original flaw was eradicated")
    checks: List[ValidationCheck] = Field(default_factory=list, description="Itemized validation checks")
    findings_before: int = Field(0, description="Count of findings detected before patch")
    findings_after: int = Field(0, description="Count of findings detected after patch")
    new_findings_count: int = Field(0, description="Count of any new security issues introduced")
    new_findings: List[Finding] = Field(default_factory=list, description="Any new findings introduced")
    summary: str = Field(..., description="Executive summary of validation results")
    message: Optional[str] = Field(None, description="Human-readable validation diagnostic message")
    status_message: Optional[str] = Field(None, description="Alias for summary/message")
    requires_human_review: bool = Field(True, description="Whether human review is required before merging")
    created_at: str = Field(..., description="ISO 8601 creation timestamp")
    completed_at: Optional[str] = Field(None, description="ISO 8601 completion timestamp")

    model_config = ConfigDict(from_attributes=True)

    def model_post_init(self, __context: Any) -> None:
        if self.validation_id is None:
            self.validation_id = self.id
        elif self.id is None:
            self.id = self.validation_id
        if self.message is None and self.summary:
            self.message = self.summary
        elif self.summary is None and self.message:
            self.summary = self.message
        if self.status_message is None:
            self.status_message = self.summary or self.message


# ============================================================================
# 5. Error Contract
# ============================================================================

class ErrorResponse(BaseModel):
    error_code: str = Field(..., description="Standard machine-readable error code")
    message: str = Field(..., description="Human-readable error description")
    request_id: Optional[str] = Field(None, description="Request trace identifier")

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# 6. Secure IoT Firmware & Synthesis Contracts
# ============================================================================

class FirmwareAnalysisRequest(BaseModel):
    target_platform: str = Field(default="esp32", description="Target platform: esp32, stm32, freertos, zephyr, arduino, rp2040, generic_embedded")
    rtos: Optional[str] = Field(default=None, description="RTOS environment: freertos, zephyr, none")
    source_code: str = Field(..., min_length=1, description="C/C++ firmware source code to analyze")
    filename: Optional[str] = Field(default="main.c", description="Virtual filename")
    security_checks: List[str] = Field(
        default_factory=lambda: ["memory", "communication", "ota_update", "device_auth", "embedded_system"],
        description="Firmware risk domains to inspect"
    )


class FirmwareAnalysisResponse(BaseModel):
    scan_id: str
    target_platform: str
    rtos: Optional[str] = None
    status: str = "completed"
    lines_of_code: int = 0
    duration_ms: float = 0.0
    firmware_components_analyzed: int = 1
    risk_breakdown: Dict[str, int] = Field(default_factory=dict)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    findings: List[Finding] = Field(default_factory=list)
    tool_status: Dict[str, Any] = Field(default_factory=dict)
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class FirmwareSynthesisRequest(BaseModel):
    requirement: str = Field(..., min_length=3, description="Natural-language description of firmware component")
    target_platform: str = Field(default="esp32", description="Target platform: esp32, stm32, freertos, zephyr, arduino, rp2040, generic_embedded")
    rtos: Optional[str] = Field(default="freertos", description="RTOS: freertos, zephyr, baremetal")
    compiler: Optional[str] = Field(default="gcc", description="Compiler toolchain")
    component_type: Optional[str] = Field(default="custom", description="Component category: mqtt_client, tls_module, ota_handler, input_validation, credential_management, watchdog, custom")


class FirmwareSynthesisResponse(BaseModel):
    id: str
    requirement: str
    target_platform: str
    rtos: Optional[str]
    component_type: str
    title: str
    source_code: str
    header_code: str
    configuration_file: Optional[str] = None
    dependencies: List[str] = Field(default_factory=list)
    security_considerations: List[str] = Field(default_factory=list)
    unit_tests: str
    explanation: str
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class FirmwareRefactorRequest(BaseModel):
    insecure_code: str = Field(..., min_length=1, description="Insecure C/C++ function to refactor")
    target_platform: str = Field(default="generic_embedded", description="Target platform")
    function_name: Optional[str] = None
    vulnerability_context: Optional[str] = None


class FirmwareRefactorResponse(BaseModel):
    secure_code: str
    explanation: str
    diff: str
    security_benefits: List[str] = Field(default_factory=list)
    target_platform: str

    model_config = ConfigDict(from_attributes=True)


class FirmwareTemplate(BaseModel):
    id: str
    title: str
    category: str
    target_platform: str
    description: str
    sample_prompt: str
