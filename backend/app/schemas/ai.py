"""Pydantic schemas for the AI finding analysis and patch generation service."""

from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ChangeItem(BaseModel):
    description: str = Field(..., min_length=1, description="Description of the specific change")
    lines_affected: str = Field(..., min_length=1, description="Lines or code region affected (e.g., 'lines 12-14')")

    model_config = ConfigDict(from_attributes=True)


class AIPatchProposal(BaseModel):
    summary: str = Field(..., min_length=1, description="Executive summary of the secure fix")
    rationale: str = Field(..., min_length=1, description="Security rationale explaining why this eliminates the flaw")
    patched_code: str = Field(..., min_length=1, description="Full or excerpted securely patched code")
    changes: List[ChangeItem] = Field(default_factory=list, description="Structured itemized changes made")
    limitations: List[str] = Field(default_factory=list, description="Known limitations or assumptions of the proposed patch")

    model_config = ConfigDict(from_attributes=True)


class AIFindingAnalysis(BaseModel):
    explanation: str = Field(..., min_length=1, description="Plain-language explanation of the finding")
    potential_impact: str = Field(..., min_length=1, description="Potential real-world security impact if exploited")
    flagged_reason: str = Field(..., min_length=1, description="Why the static scanner flagged this specific pattern")
    recommended_remediation: str = Field(..., min_length=1, description="Specific recommended remediation strategy")
    secure_coding_guidance: List[str] = Field(default_factory=list, description="Authoritative secure coding principles")
    uncertainties_and_assumptions: List[str] = Field(default_factory=list, description="Uncertainties and contextual assumptions")
    scanner_evidence_distinction: str = Field(
        ...,
        description="Explicit statement distinguishing objective scanner evidence from AI interpretation"
    )

    model_config = ConfigDict(from_attributes=True)


class AIExecutionMetadata(BaseModel):
    provider: str
    model: str
    status: str  # SUCCESS, UNCONFIGURED, RATE_LIMIT_ERROR, AUTH_ERROR, NETWORK_ERROR, SCHEMA_ERROR, TIMEOUT
    duration_ms: float
    error_category: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AIAnalysisResult(BaseModel):
    success: bool
    analysis: Optional[AIFindingAnalysis] = None
    metadata: AIExecutionMetadata
    error_message: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AIPatchResult(BaseModel):
    success: bool
    proposal: Optional[AIPatchProposal] = None
    requires_review: bool = True
    validation_state: str = "UNVALIDATED"
    metadata: AIExecutionMetadata
    error_message: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
