"""Scans API endpoints for code snippets, uploaded files, and repositories."""

import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, File, HTTPException, Query, UploadFile, status
from app.config import settings
from app.schemas.finding import FindingResponse
from app.schemas.scan import (
    ScanCodeRequest,
    ScanRepoRequest,
    ScanResponse,
    ScanSummary
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
    get_findings_by_scan_id,
    get_scan,
    list_scans,
    save_finding,
    save_scan
)

router = APIRouter(prefix="/api/scans", tags=["Scans"])


def _to_legacy_findings(findings) -> List[FindingResponse]:
    res = []
    for f in findings:
        if isinstance(f, FindingResponse):
            res.append(f)
        elif isinstance(f, dict):
            res.append(
                FindingResponse(
                    id=f["id"],
                    scan_id=f["scan_id"],
                    rule_id=f.get("rule_id") or f.get("cwe_id", "VULN-GENERIC"),
                    cwe_id=f["cwe_id"],
                    title=f["title"],
                    severity=f["severity"].upper(),
                    description=f["description"],
                    file_path=f["file_path"],
                    line_number=f.get("line_start") or f.get("line_number"),
                    code_snippet=f.get("code_snippet") or (f.get("evidence", {}).get("snippet") if isinstance(f.get("evidence"), dict) else None),
                    recommendation=f.get("recommendation")
                )
            )
        else:
            res.append(
                FindingResponse(
                    id=f.id,
                    scan_id=f.scan_id,
                    rule_id=getattr(f, "rule_id", None) or f.cwe_id,
                    cwe_id=f.cwe_id,
                    title=f.title,
                    severity=f.severity.upper(),
                    description=f.description,
                    file_path=f.file_path,
                    line_number=f.line_start or getattr(f, "line_number", None),
                    code_snippet=f.code_snippet,
                    recommendation=f.recommendation
                )
            )
    return res


def _to_legacy_summary(s) -> ScanSummary:
    if isinstance(s, ScanSummary):
        return s
    if isinstance(s, dict):
        total = s.get("total", s.get("total_findings", 0))
        crit = s.get("critical", s.get("critical_count", 0))
        high = s.get("high", s.get("high_count", 0))
        med = s.get("medium", s.get("medium_count", 0))
        low = s.get("low", s.get("low_count", 0))
        return ScanSummary(
            total_findings=total,
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low
        )
    return ScanSummary(
        total_findings=getattr(s, "total", 0),
        critical_count=getattr(s, "critical", 0),
        high_count=getattr(s, "high", 0),
        medium_count=getattr(s, "medium", 0),
        low_count=getattr(s, "low", 0)
    )


@router.post("/code", response_model=ScanResponse)
def scan_inline_code(request: ScanCodeRequest):
    """Scans raw source code string for security vulnerabilities."""
    validate_source_code_size(request.source_code)
    clean_file_name = sanitize_filename(request.file_name or "snippet.py")

    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    raw_findings = ScannerService.scan_code(
        source_code=request.source_code,
        file_path=clean_file_name,
        language=request.language or "python"
    )

    normalized_findings, summary = FindingNormalizer.normalize(raw_findings, scan_id=scan_id)

    # Persist scan
    scan_record = {
        "id": scan_id,
        "source_type": "source_code",
        "target_type": "code",
        "target_name": clean_file_name,
        "status": "completed",
        "language": request.language or "python",
        "summary": summary.model_dump(),
        "source_code": request.source_code,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    save_scan(scan_record)

    # Persist findings
    for f in normalized_findings:
        save_finding(f.model_dump())

    return ScanResponse(
        id=scan_id,
        target_type="code",
        target_name=clean_file_name,
        status="completed",
        language=request.language or "python",
        summary=_to_legacy_summary(summary),
        findings=_to_legacy_findings(normalized_findings),
        created_at=scan_record["created_at"]
    )


@router.post("/file", response_model=ScanResponse)
async def scan_uploaded_file(file: UploadFile = File(...)):
    """Uploads and scans a single source code file."""
    clean_file_name = sanitize_filename(file.filename or "uploaded_file.py")

    content_bytes = await file.read()
    if len(content_bytes) > settings.max_scan_file_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds max size limit of {settings.max_scan_file_size_bytes} bytes."
        )

    try:
        content_str = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be valid UTF-8 encoded text."
        )

    validate_source_code_size(content_str)

    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    raw_findings = ScannerService.scan_code(
        source_code=content_str,
        file_path=clean_file_name
    )

    normalized_findings, summary = FindingNormalizer.normalize(raw_findings, scan_id=scan_id)

    scan_record = {
        "id": scan_id,
        "source_type": "source_code",
        "target_type": "file",
        "target_name": clean_file_name,
        "status": "completed",
        "language": "python" if clean_file_name.endswith(".py") else "generic",
        "summary": summary.model_dump(),
        "source_code": content_str,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    save_scan(scan_record)

    for f in normalized_findings:
        save_finding(f.model_dump())

    return ScanResponse(
        id=scan_id,
        target_type="file",
        target_name=clean_file_name,
        status="completed",
        language=scan_record["language"],
        summary=_to_legacy_summary(summary),
        findings=_to_legacy_findings(normalized_findings),
        created_at=scan_record["created_at"]
    )


@router.post("/repository", response_model=ScanResponse)
def scan_repository(request: ScanRepoRequest):
    """
    Safely clones and scans an authorized git repository.
    Enforces SSRF defense, timeouts, depth limits, and max clone size.
    """
    validate_repository_url(request.repo_url)

    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    raw_findings = RepositoryService.clone_and_scan(
        repo_url=request.repo_url,
        branch=request.branch or "main",
        auth_token=request.auth_token
    )

    normalized_findings, summary = FindingNormalizer.normalize(raw_findings, scan_id=scan_id)

    scan_record = {
        "id": scan_id,
        "source_type": "repository",
        "target_type": "repository",
        "target_name": request.repo_url,
        "status": "completed",
        "language": "multi-file",
        "summary": summary.model_dump(),
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    save_scan(scan_record)

    for f in normalized_findings:
        save_finding(f.model_dump())

    return ScanResponse(
        id=scan_id,
        target_type="repository",
        target_name=request.repo_url,
        status="completed",
        language="multi-file",
        summary=_to_legacy_summary(summary),
        findings=_to_legacy_findings(normalized_findings),
        created_at=scan_record["created_at"]
    )


@router.get("", response_model=List[ScanResponse])
def get_scan_history(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
    """Retrieves paginated scan history."""
    scans_raw = list_scans(limit=limit, offset=offset)
    results = []
    for s in scans_raw:
        findings_raw = get_findings_by_scan_id(s["id"])
        summary_dict = s.get("summary") or {}
        target_t = s.get("target_type") or s.get("source_type") or "code"
        results.append(
            ScanResponse(
                id=s["id"],
                target_type=target_t,
                target_name=s["target_name"],
                status=s["status"],
                language=s.get("language"),
                summary=_to_legacy_summary(summary_dict),
                findings=_to_legacy_findings(findings_raw),
                created_at=s["created_at"]
            )
        )
    return results


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan_by_id(scan_id: str):
    """Retrieves details of a specific scan and all its identified vulnerabilities."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found."
        )

    findings = get_findings_by_scan_id(scan_id)
    summary_dict = scan.get("summary") or {}
    target_t = scan.get("target_type") or scan.get("source_type") or "code"

    return ScanResponse(
        id=scan["id"],
        target_type=target_t,
        target_name=scan["target_name"],
        status=scan["status"],
        language=scan.get("language"),
        summary=_to_legacy_summary(summary_dict),
        findings=_to_legacy_findings(findings),
        created_at=scan["created_at"]
    )
