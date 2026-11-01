"""Validation retrieval API endpoint for Vulnex API v1."""

from fastapi import APIRouter, HTTPException, Request, status
from app.schemas.v1 import Finding, ValidationResult
from app.storage.database import get_validation

router = APIRouter(prefix="/validations", tags=["Validations"])


@router.get("/{validation_id}", response_model=ValidationResult)
def get_validation_by_id(validation_id: str, request: Request):
    """Return validation progress, compilation status, and actual regression check results."""
    val = get_validation(validation_id)
    if not val:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Validation with ID '{validation_id}' not found."
        )

    # Reconstruct new_findings if present
    new_findings_raw = val.get("new_findings") or []
    new_findings = []
    if isinstance(new_findings_raw, list):
        for item in new_findings_raw:
            if isinstance(item, dict):
                try:
                    new_findings.append(Finding(**item))
                except Exception:
                    pass

    checks_raw = val.get("checks") or []
    checks = []
    if isinstance(checks_raw, list):
        for c in checks_raw:
            if isinstance(c, dict):
                try:
                    from app.schemas.v1 import ValidationCheck
                    checks.append(ValidationCheck(**c))
                except Exception:
                    pass

    summary_text = val.get("summary") or val.get("message", "")

    return ValidationResult(
        id=val["id"],
        validation_id=val["id"],
        remediation_id=val["remediation_id"],
        status=val.get("status", "completed"),
        is_valid=bool(val["is_valid"]),
        syntax_valid=bool(val["syntax_valid"]),
        target_vulnerability_eradicated=bool(val["target_vulnerability_eradicated"]),
        checks=checks,
        findings_before=val.get("findings_before", 0),
        findings_after=val.get("findings_after", 0),
        new_findings_count=val.get("new_findings_count", 0),
        new_findings=new_findings,
        summary=summary_text,
        message=summary_text,
        status_message=summary_text,
        requires_human_review=bool(val.get("requires_human_review", True)),
        created_at=val["created_at"],
        completed_at=val.get("completed_at")
    )
