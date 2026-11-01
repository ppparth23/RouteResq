"""Pydantic schemas for remediation and AI explanation."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.schemas.validation import ValidationResponse


class RemediationExplainRequest(BaseModel):
    finding_id: Optional[str] = Field(None, description="Optional finding ID to explain")
    rule_id: Optional[str] = Field(None, description="Scanner rule ID (e.g. VULN-SQLI-001)")
    cwe_id: Optional[str] = Field(None, description="CWE identifier (e.g. CWE-89)")
    code_snippet: str = Field(..., description="Vulnerable code snippet to analyze")
    context_code: Optional[str] = Field(None, description="Surrounding contextual code")


class RemediationExplainResponse(BaseModel):
    explanation: str = Field(..., description="Clear explanation of the vulnerability and attack vector")
    risk_analysis: str = Field(..., description="Impact and severity breakdown")
    safe_coding_guidelines: List[str] = Field(default_factory=list, description="Recommended architectural and coding patterns")
    references: List[str] = Field(default_factory=list, description="Authoritative reference links (OWASP, CWE, etc.)")


class PatchGenerateRequest(BaseModel):
    scan_id: Optional[str] = Field(None, description="Scan ID containing finding")
    finding_id: Optional[str] = Field(None, description="Finding ID being remediated")
    source_code: str = Field(..., description="Full source code or vulnerable snippet to fix")
    rule_id: Optional[str] = Field(None, description="Scanner rule ID")
    cwe_id: Optional[str] = Field(None, description="CWE ID being fixed")
    file_name: Optional[str] = Field("source.py", description="Filename for context")


class PatchGenerateResponse(BaseModel):
    remediation_id: str = Field(..., description="Unique remediation record ID")
    finding_id: Optional[str] = Field(None, description="Associated finding ID")
    original_code: str = Field(..., description="Original code before fix")
    patched_code: str = Field(..., description="Safely repaired source code")
    unified_diff: str = Field(..., description="Unified diff showing exact changes")
    explanation: str = Field(..., description="AI explanation of the repair applied")
    validation_status: str = Field(..., description="Validation outcome: VALIDATED, SYNTAX_ERROR, REGRESSION_DETECTED, UNVERIFIED")
    validation_details: Optional[ValidationResponse] = Field(None, description="Detailed validation results")
