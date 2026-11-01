"""Patch validation API endpoints."""

from fastapi import APIRouter
from app.schemas.finding import FindingResponse
from app.schemas.validation import ValidationRequest, ValidationResponse
from app.services.validation_service import ValidationService

router = APIRouter(prefix="/api/validation", tags=["Validation"])


@router.post("/validate-patch", response_model=ValidationResponse)
def validate_patch(request: ValidationRequest):
    """
    Validates a proposed code patch against the original code.
    Checks:
    1. Syntax validity (AST compilation without arbitrary execution).
    2. Elimination of the target CWE vulnerability.
    3. Absence of newly introduced security regressions.
    """
    result = ValidationService.validate_patch(
        original_code=request.original_code,
        patched_code=request.patched_code,
        target_cwe_id=request.target_cwe_id,
        file_name=request.file_name or "remediated.py"
    )

    legacy_findings = []
    for f in result.new_findings:
        legacy_findings.append(
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
        )

    return ValidationResponse(
        is_valid=result.is_valid,
        syntax_valid=result.syntax_valid,
        target_vulnerability_eradicated=result.target_vulnerability_eradicated,
        new_findings_count=result.new_findings_count,
        new_findings=legacy_findings,
        status_message=result.message
    )
