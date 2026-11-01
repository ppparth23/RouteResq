"""Pydantic schemas for security scans."""

from typing import Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.schemas.finding import FindingResponse


class ScanCodeRequest(BaseModel):
    source_code: str = Field(..., description="Source code text to scan")
    file_name: Optional[str] = Field("snippet.py", description="Virtual or actual filename")
    language: Optional[str] = Field("python", description="Language of the code (e.g., python, javascript)")


class ScanRepoRequest(BaseModel):
    repo_url: str = Field(..., description="Authorized git repository HTTPS URL")
    branch: Optional[str] = Field("main", description="Branch to checkout")
    auth_token: Optional[str] = Field(None, description="Optional bearer or personal access token for private repository")


class ScanSummary(BaseModel):
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    total: Optional[int] = None
    critical: Optional[int] = None
    high: Optional[int] = None
    medium: Optional[int] = None
    low: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)

    def model_post_init(self, __context: Any) -> None:
        if self.total_findings == 0 and self.total:
            self.total_findings = self.total
        if self.critical_count == 0 and self.critical:
            self.critical_count = self.critical
        if self.high_count == 0 and self.high:
            self.high_count = self.high
        if self.medium_count == 0 and self.medium:
            self.medium_count = self.medium
        if self.low_count == 0 and self.low:
            self.low_count = self.low


class ScanResponse(BaseModel):
    id: str = Field(..., description="Unique scan ID")
    target_type: str = Field(..., description="Target type: code, file, or repository")
    target_name: str = Field(..., description="Name or URL of target")
    status: str = Field(..., description="Scan status: completed, failed, partial")
    language: Optional[str] = Field(None, description="Primary detected or specified language")
    summary: ScanSummary = Field(default_factory=ScanSummary)
    findings: List[FindingResponse] = Field(default_factory=list)
    created_at: str = Field(..., description="Timestamp of scan execution")

    model_config = ConfigDict(from_attributes=True)


class ScanListResponse(BaseModel):
    total: int
    scans: List[ScanResponse]
