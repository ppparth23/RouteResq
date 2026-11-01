"""Storage models for Vulnex AI."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass
class ScanRecord:
    id: str
    target_type: str
    target_name: str
    status: str
    language: Optional[str] = None
    summary: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class FindingRecord:
    id: str
    scan_id: str
    rule_id: str
    cwe_id: str
    title: str
    severity: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class RemediationRecord:
    id: str
    scan_id: str
    finding_id: str
    original_code: str
    patched_code: str
    unified_diff: str
    validation_status: str
    explanation: Optional[str] = None
    validation_details: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
