"""Pydantic schemas for patch validation."""

from typing import List, Optional
from pydantic import BaseModel, Field
from app.schemas.finding import FindingResponse


class ValidationRequest(BaseModel):
    original_code: str = Field(..., description="Original vulnerable code")
    patched_code: str = Field(..., description="Proposed remediated code")
    target_cwe_id: Optional[str] = Field(None, description="CWE ID targeted for remediation (e.g. CWE-89)")
    file_name: Optional[str] = Field("source.py", description="Target file name for context")


class ValidationResponse(BaseModel):
    is_valid: bool = Field(..., description="True if patch is syntactically sound and eradicates target flaw with no regressions")
    syntax_valid: bool = Field(..., description="True if code compiles/parses without syntax error")
    target_vulnerability_eradicated: bool = Field(..., description="True if target CWE is no longer detected")
    new_findings_count: int = Field(0, description="Count of any newly introduced security findings")
    new_findings: List[FindingResponse] = Field(default_factory=list, description="Any new vulnerabilities found in patched code")
    status_message: str = Field(..., description="Human-readable validation diagnostic message")
