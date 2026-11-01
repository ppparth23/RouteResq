"""Findings and finding-specific remediation API endpoints for Vulnex API v1."""

from datetime import datetime, timezone
import uuid
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, status
from app.schemas.v1 import Finding, RemediationRequest, RemediationResponse
from app.services.patch_service import PatchService
from app.services.validation_service import ValidationService
from app.storage.database import (
    get_finding,
    get_scan,
    save_remediation,
    save_validation,
)

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("/{finding_id}", response_model=Finding)
def get_finding_by_id(finding_id: str, request: Request):
    """Retrieve detailed vulnerability finding by finding ID, including evidence and source location."""
    record = get_finding(finding_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found."
        )
    return Finding(**record)


@router.post("/{finding_id}/remediations", response_model=RemediationResponse, status_code=status.HTTP_201_CREATED)
async def create_finding_remediation(
    finding_id: str,
    remediation_req: RemediationRequest,
    request: Request
):
    """
    Create a remediation request for a specific finding.
    Executes the 10-step secure repair workflow, calculates unified diff,
    persists isolated artifacts, and returns remediation metadata.
    """
    finding = get_finding(finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found."
        )

    try:
        result = await PatchService.remediate_finding(
            finding_id=finding_id,
            prompt_context=remediation_req.prompt_context,
            auto_validate=remediation_req.auto_validate
        )
        return RemediationResponse(
            id=result["id"],
            finding_id=result["finding_id"],
            scan_id=result["scan_id"],
            status=result["status"],
            summary=result.get("patch_summary") or result.get("summary"),
            explanation=result.get("explanation"),
            limitations=result.get("limitations") or [],
            original_hash=result.get("original_hash"),
            proposed_hash=result.get("proposed_hash"),
            provider=result.get("provider"),
            model=result.get("model"),
            validation_status=result.get("validation_status", "UNVALIDATED"),
            requires_review=bool(result.get("requires_review", True)),
            artifact_path=result.get("artifact_path"),
            added_lines=result.get("added_lines", 0),
            removed_lines=result.get("removed_lines", 0),
            created_at=result["created_at"],
            updated_at=result.get("updated_at", result["created_at"]),
            error_message=result.get("error_message")
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except Exception as e:
        now_iso = datetime.now(timezone.utc).isoformat()
        err_id = f"rem_{uuid.uuid4().hex[:12]}"
        return RemediationResponse(
            id=err_id,
            finding_id=finding_id,
            scan_id=finding.get("scan_id", ""),
            status="failed",
            summary="Remediation failed",
            explanation=None,
            limitations=[str(e)],
            validation_status="UNVALIDATED",
            requires_review=True,
            created_at=now_iso,
            updated_at=now_iso,
            error_message=str(e)
        )
