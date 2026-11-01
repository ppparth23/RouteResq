"""Scans endpoints and scan history for Vulnex API v1."""

from datetime import datetime, timezone
import math
import uuid
from typing import List, Optional, Union
from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile, status
from app.config import settings
from app.schemas.v1 import (
    CombinedRemediationResponse,
    Finding,
    PaginatedScanHistory,
    RepositoryScanRequest,
    ScanResponse,
    ScanSummary,
    SourceCodeScanRequest
)
from app.security.input_validation import (
    sanitize_filename,
    validate_repository_url,
    validate_source_code_size
)
from app.services.finding_normalizer import FindingNormalizer
from app.services.repository_service import RepositoryService
from app.services.scanner import ScannerService
from app.storage.database import (
    clear_all_scans,
    get_findings_by_scan_id,
    get_scan,
    list_scans_paginated,
    save_finding,
    save_scan
)

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    scan_req: Union[SourceCodeScanRequest, RepositoryScanRequest],
    request: Request
):
    """
    Initiate static security scan for source code or an authorized repository.
    Returns the unique scan identifier, initial lifecycle state, and summary.
    """
    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    if scan_req.source_type == "source_code":
        from app.services.scanners.pipeline import ScanningPipeline
        pipeline = ScanningPipeline(timeout_seconds=settings.repo_clone_timeout_seconds)
        response, findings = pipeline.execute_scan(
            source_code=scan_req.source_code,
            filename=scan_req.filename or "example.py",
            language=scan_req.language or "python",
            scan_id=scan_id,
            target_platform=getattr(scan_req, "target_platform", "generic"),
            rtos=getattr(scan_req, "rtos", None),
            compiler=getattr(scan_req, "compiler", None)
        )
        return response

    elif scan_req.source_type == "repository":
        validate_repository_url(scan_req.repo_url)

        try:
            raw_findings = RepositoryService.clone_and_scan(
                repo_url=scan_req.repo_url,
                branch=scan_req.branch or "main",
                auth_token=scan_req.auth_token
            )
            normalized_findings, summary = FindingNormalizer.normalize(raw_findings, scan_id=scan_id)

            scan_record = {
                "id": scan_id,
                "source_type": "repository",
                "target_name": scan_req.repo_url,
                "status": "completed",
                "language": "multi-language",
                "summary": summary.model_dump(),
                "source_code": None,
                "created_at": now_iso,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "error_message": None
            }
            save_scan(scan_record)

            for f in normalized_findings:
                save_finding(f.model_dump())

            return ScanResponse(
                id=scan_id,
                source_type="repository",
                target_name=scan_req.repo_url,
                status="completed",
                language="multi-language",
                summary=summary,
                created_at=now_iso,
                completed_at=scan_record["completed_at"],
                error_message=None
            )

        except HTTPException:
            raise
        except Exception as e:
            failed_record = {
                "id": scan_id,
                "source_type": "repository",
                "target_name": scan_req.repo_url,
                "status": "failed",
                "language": "multi-language",
                "summary": ScanSummary().model_dump(),
                "source_code": None,
                "created_at": now_iso,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "error_message": str(e)
            }
            save_scan(failed_record)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Repository scan failed: {str(e)}"
            )

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported source_type: {getattr(scan_req, 'source_type', 'unknown')}"
        )


@router.post("/upload", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def upload_and_scan(
    file: UploadFile = File(...),
    language: Optional[str] = Form("python"),
    request: Request = None
):
    """
    Upload a source code file or a project ZIP archive and execute real security scanning.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No filename provided in upload."
        )

    clean_filename = sanitize_filename(file.filename)
    contents = await file.read()

    from app.services.scanners.pipeline import ScanningPipeline
    pipeline = ScanningPipeline(timeout_seconds=settings.repo_clone_timeout_seconds)

    if clean_filename.lower().endswith(".zip"):
        response, _ = pipeline.execute_scan_zip(
            zip_bytes=contents,
            zip_filename=clean_filename
        )
        return response
    else:
        # Standard source code file upload
        try:
            source_code = contents.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file must be valid UTF-8 encoded text."
            )

        response, _ = pipeline.execute_scan(
            source_code=source_code,
            filename=clean_filename,
            language=language or "python"
        )
        return response


@router.delete("", status_code=status.HTTP_200_OK)
def delete_all_scans(request: Request = None):
    """
    Clear all scan history and associated findings.
    Allows users to reset state to 0 for a clean demonstration.
    """
    clear_all_scans()
    return {"message": "All scan history and findings successfully cleared.", "total_scans": 0}


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan_by_id(scan_id: str, request: Request):
    """Return the current scan state and summary."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found."
        )

    summary_dict = scan.get("summary") or {}
    summary = ScanSummary(**summary_dict) if isinstance(summary_dict, dict) else ScanSummary()

    return ScanResponse(
        id=scan["id"],
        source_type=scan.get("source_type", "source_code"),
        target_name=scan["target_name"],
        status=scan["status"],
        language=scan.get("language"),
        summary=summary,
        created_at=scan["created_at"],
        completed_at=scan.get("completed_at"),
        lines_of_code=scan.get("lines_of_code", 0),
        duration_ms=scan.get("duration_ms", 0.0),
        files_count=scan.get("files_count", 1),
        vulnerability_density=scan.get("vulnerability_density", 0.0),
        target_platform=scan.get("target_platform", "generic"),
        rtos=scan.get("rtos"),
        compiler=scan.get("compiler"),
        tool_status=scan.get("tool_status"),
        error_message=scan.get("error_message")
    )


@router.get("/{scan_id}/findings", response_model=List[Finding])
def get_scan_findings(scan_id: str, request: Request):
    """Return all normalized findings associated with a specific scan."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found."
        )

    findings_raw = get_findings_by_scan_id(scan_id)
    return [Finding(**f) for f in findings_raw]


@router.get("/{scan_id}/combined_remediation", response_model=CombinedRemediationResponse)
def get_combined_remediation(scan_id: str, request: Request = None):
    """
    Returns the complete, combined source code with ALL detected vulnerabilities
    simultaneously remediated into one clean, compilable file.
    """
    from app.services.patch_service import PatchService
    res = PatchService.synthesize_combined_source(scan_id)
    return CombinedRemediationResponse(**res)


@router.get("", response_model=PaginatedScanHistory)
def get_scan_history(
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    request: Request = None
):
    """Return paginated scan history."""
    offset = (page - 1) * limit
    scans_raw, total = list_scans_paginated(limit=limit, offset=offset)

    items = []
    for s in scans_raw:
        summary_dict = s.get("summary") or {}
        summary = ScanSummary(**summary_dict) if isinstance(summary_dict, dict) else ScanSummary()
        items.append(
            ScanResponse(
                id=s["id"],
                source_type=s.get("source_type", "source_code"),
                target_name=s["target_name"],
                status=s["status"],
                language=s.get("language"),
                summary=summary,
                created_at=s["created_at"],
                completed_at=s.get("completed_at"),
                lines_of_code=s.get("lines_of_code", 0),
                duration_ms=s.get("duration_ms", 0.0),
                files_count=s.get("files_count", 1),
                vulnerability_density=s.get("vulnerability_density", 0.0),
                error_message=s.get("error_message")
            )
        )

    pages = math.ceil(total / limit) if total > 0 else 1

    return PaginatedScanHistory(
        items=items,
        total=total,
        page=page,
        limit=limit,
        pages=pages
    )
