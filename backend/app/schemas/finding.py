"""Pydantic schemas for vulnerability findings."""

from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class FindingBase(BaseModel):
    rule_id: str = Field(..., description="Unique scanner rule identifier, e.g. VULN-SQLI-001")
    cwe_id: str = Field(..., description="Common Weakness Enumeration ID, e.g. CWE-89")
    title: str = Field(..., description="Short finding title")
    severity: str = Field(..., description="Finding severity: CRITICAL, HIGH, MEDIUM, LOW")
    description: str = Field(..., description="Detailed description of the vulnerability")
    file_path: str = Field(..., description="Relative or base file path")
    line_number: Optional[int] = Field(None, description="Line number where issue originates")
    code_snippet: Optional[str] = Field(None, description="Extracted vulnerable code snippet")
    recommendation: Optional[str] = Field(None, description="Standard remediation guideline")


class FindingResponse(FindingBase):
    id: str = Field(..., description="Unique finding ID")
    scan_id: str = Field(..., description="Scan ID associated with this finding")
    created_at: Optional[str] = Field(None, description="Timestamp of finding creation")

    model_config = ConfigDict(from_attributes=True)
