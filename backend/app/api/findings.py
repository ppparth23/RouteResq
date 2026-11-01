"""Findings retrieval API endpoints."""

from fastapi import APIRouter, HTTPException, status
from app.schemas.finding import FindingResponse
from app.storage.database import get_finding

router = APIRouter(prefix="/api/findings", tags=["Findings"])


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding_by_id(finding_id: str):
    """Retrieve detailed vulnerability finding by finding ID."""
    finding = get_finding(finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID '{finding_id}' not found."
        )
    return finding
