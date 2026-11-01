"""Remediation lifecycle, diff inspection, and patch validation endpoints for Vulnex API v1."""

from fastapi import APIRouter, HTTPException, Request, status
from app.schemas.v1 import CodeDiff, RemediationResponse, ValidationRequest, ValidationResult
from app.services.validation_service import ValidationService
from app.storage.database import (
    get_finding,
    get_remediation,
    save_remediation,
    save_validation
)

router = APIRouter(prefix="/remediations", tags=["Remediations"])


@router.get("/{remediation_id}", response_model=RemediationResponse)
def get_remediation_by_id(remediation_id: str, request: Request):
    """Return the remediation status and available result metadata."""
    rem = get_remediation(remediation_id)
    if not rem:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation with ID '{remediation_id}' not found."
        )

    return RemediationResponse(
        id=rem["id"],
        finding_id=rem["finding_id"],
        scan_id=rem["scan_id"],
        status=rem.get("status", "completed"),
        summary=rem.get("patch_summary") or rem.get("summary"),
        explanation=rem.get("explanation"),
        limitations=rem.get("limitations") or [],
        original_hash=rem.get("original_hash"),
        proposed_hash=rem.get("proposed_hash"),
        provider=rem.get("provider"),
        model=rem.get("model"),
        validation_status=rem.get("validation_status", "UNVALIDATED"),
        requires_review=bool(rem.get("requires_review", True)),
        artifact_path=rem.get("artifact_path"),
        added_lines=rem.get("added_lines", 0),
        removed_lines=rem.get("removed_lines", 0),
        created_at=rem["created_at"],
        updated_at=rem.get("updated_at", rem["created_at"]),
        error_message=rem.get("error_message")
    )


@router.get("/{remediation_id}/diff", response_model=CodeDiff)
def get_remediation_diff(remediation_id: str, request: Request):
    """Return the original and proposed code along with structured unified diff."""
    rem = get_remediation(remediation_id)
    if not rem:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation with ID '{remediation_id}' not found."
        )

    finding = get_finding(rem["finding_id"])
    file_path = finding["file_path"] if finding else "source.py"

    diff_str = rem.get("unified_diff", "")
    added_lines = rem.get("added_lines")
    removed_lines = rem.get("removed_lines")
    if added_lines is None or removed_lines is None:
        added_lines = sum(1 for line in diff_str.splitlines() if line.startswith("+") and not line.startswith("+++"))
        removed_lines = sum(1 for line in diff_str.splitlines() if line.startswith("-") and not line.startswith("---"))

    return CodeDiff(
        remediation_id=rem["id"],
        finding_id=rem["finding_id"],
        file_path=file_path,
        original_code=rem.get("original_code", ""),
        proposed_code=rem.get("patched_code", ""),
        unified_diff=diff_str,
        changes_count=added_lines + removed_lines,
        added_lines=added_lines,
        removed_lines=removed_lines,
        original_hash=rem.get("original_hash"),
        proposed_hash=rem.get("proposed_hash"),
        summary=rem.get("patch_summary") or rem.get("summary"),
        explanation=rem.get("explanation"),
        limitations=rem.get("limitations") or [],
        validation_status=rem.get("validation_status", "UNVALIDATED"),
        requires_review=bool(rem.get("requires_review", True))
    )


@router.post("/{remediation_id}/validate", response_model=ValidationResult, status_code=status.HTTP_201_CREATED)
def validate_remediation(
    remediation_id: str,
    val_req: ValidationRequest = ValidationRequest(),
    request: Request = None
):
    """
    Request isolated verification and regression re-scanning of the proposed patch.
    Executes the 10-step secure validation pipeline, recording individual check outputs.
    """
    rem = get_remediation(remediation_id)
    if not rem:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation with ID '{remediation_id}' not found."
        )

    val_result = ValidationService.validate_remediation(
        remediation_id=remediation_id,
        strict_mode=val_req.strict_mode,
        trusted_test_command=val_req.trusted_test_command
    )

    # Update remediation validation status
    new_status = "VALIDATED" if val_result.is_valid else ("VALIDATION_UNAVAILABLE" if val_result.status == "validation_unavailable" else "VALIDATION_FAILED")
    rem["validation_status"] = new_status
    save_remediation(rem)

    return val_result
