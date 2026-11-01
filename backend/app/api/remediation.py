"""Remediation and AI explanation API endpoints."""

from fastapi import APIRouter, HTTPException, status
from app.schemas.finding import FindingResponse
from app.schemas.remediation import (
    RemediationExplainRequest,
    RemediationExplainResponse,
    PatchGenerateRequest,
    PatchGenerateResponse
)
from app.schemas.validation import ValidationResponse
from app.services.ai_service import AIService
from app.services.patch_service import PatchService
from app.services.validation_service import ValidationService
from app.storage.database import get_remediation, save_remediation

router = APIRouter(prefix="/api/remediation", tags=["Remediation"])


@router.post("/explain", response_model=RemediationExplainResponse)
async def explain_vulnerability(request: RemediationExplainRequest):
    """Explains a detected vulnerability, its attack vector, and mitigation strategy."""
    explanation_data = await AIService.explain_vulnerability(
        code_snippet=request.code_snippet,
        rule_id=request.rule_id,
        cwe_id=request.cwe_id,
        context_code=request.context_code
    )
    return RemediationExplainResponse(
        explanation=explanation_data.get("explanation", ""),
        risk_analysis=explanation_data.get("risk_analysis", ""),
        safe_coding_guidelines=explanation_data.get("safe_coding_guidelines", []),
        references=explanation_data.get("references", [])
    )


@router.post("/generate-patch", response_model=PatchGenerateResponse)
async def generate_patch(request: PatchGenerateRequest):
    """
    Synthesizes a secure code patch, creates a unified diff,
    and independently validates the patch for syntax correctness and regression avoidance.
    """
    patch_result = await PatchService.create_patch(
        source_code=request.source_code,
        finding_id=request.finding_id,
        rule_id=request.rule_id,
        cwe_id=request.cwe_id,
        file_name=request.file_name or "source.py"
    )

    # Validate the generated patch in isolation
    validation_raw = ValidationService.validate_patch(
        original_code=request.source_code,
        patched_code=patch_result["patched_code"],
        target_cwe_id=request.cwe_id,
        file_name=request.file_name or "source.py"
    )

    validation_status = "VALIDATED" if validation_raw.is_valid else "VALIDATION_FAILED"

    legacy_findings = [
        FindingResponse(
            id=f.id,
            scan_id=f.scan_id,
            rule_id=f.rule_id or f.cwe_id,
            cwe_id=f.cwe_id,
            title=f.title,
            severity=f.severity.upper(),
            description=f.description,
            file_path=f.file_path,
            line_number=f.line_start or f.line_number,
            code_snippet=f.code_snippet,
            recommendation=f.recommendation
        )
        for f in validation_raw.new_findings
    ]

    validation_details = ValidationResponse(
        is_valid=validation_raw.is_valid,
        syntax_valid=validation_raw.syntax_valid,
        target_vulnerability_eradicated=validation_raw.target_vulnerability_eradicated,
        new_findings_count=validation_raw.new_findings_count,
        new_findings=legacy_findings,
        status_message=validation_raw.message
    )

    # Persist remediation record
    remediation_record = {
        "id": patch_result["remediation_id"],
        "scan_id": request.scan_id or "adhoc_scan",
        "finding_id": request.finding_id or "adhoc_finding",
        "status": "completed",
        "original_code": patch_result["original_code"],
        "patched_code": patch_result["patched_code"],
        "unified_diff": patch_result["unified_diff"],
        "explanation": patch_result["explanation"],
        "validation_status": validation_status,
        "validation_details": validation_details.model_dump()
    }
    save_remediation(remediation_record)

    return PatchGenerateResponse(
        remediation_id=patch_result["remediation_id"],
        finding_id=request.finding_id,
        original_code=patch_result["original_code"],
        patched_code=patch_result["patched_code"],
        unified_diff=patch_result["unified_diff"],
        explanation=patch_result["explanation"],
        validation_status=validation_status,
        validation_details=validation_details
    )


@router.get("/{remediation_id}")
def get_remediation_by_id(remediation_id: str):
    """Retrieve saved remediation details and validation report."""
    rec = get_remediation(remediation_id)
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation with ID '{remediation_id}' not found."
        )
    return rec
