"""Base classes and data models for Vulnex AI security scanners."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import re
from typing import List, Optional


SECRET_PATTERNS = [
    (re.compile(r"""(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token|password|jwt[_-]?secret)\s*[:=]\s*(['"])([^'"]{6,})\2"""),
     r'\1 = \2[REDACTED_SECRET]\2'),
    (re.compile(r"""AIza[0-9A-Za-z-_]{35}"""), "[REDACTED_GEMINI_KEY]"),
    (re.compile(r"""ghp_[0-9A-Za-z]{36}"""), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"""-----BEGIN (?:RSA )?PRIVATE KEY-----[^-]+-----END (?:RSA )?PRIVATE KEY-----""", re.DOTALL),
     "[REDACTED_PRIVATE_KEY]")
]


def redact_secrets(text: Optional[str]) -> Optional[str]:
    """Redacts obvious secrets, private keys, and API tokens from code evidence and logs."""
    if not text:
        return text
    redacted = text
    for pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


@dataclass
class ScannerFinding:
    rule_id: str
    title: str
    severity: str  # critical, high, medium, low, info, unknown
    category: str
    cwe_id: Optional[str]
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    evidence: Optional[str] = None
    description: str = ""
    recommendation: Optional[str] = None
    source: str = "scanner"
    confidence: str = "high"
    cvss_score: Optional[float] = None
    cvss_version: str = "3.1"
    function_name: Optional[str] = None
    column_number: int = 1
    root_cause: Optional[str] = None
    exploitation_conditions: Optional[str] = None


@dataclass
class ScanExecutionResult:
    scanner_name: str
    success: bool
    findings: List[ScannerFinding] = field(default_factory=list)
    error_type: Optional[str] = None  # MISSING_EXECUTABLE, TIMEOUT, MALFORMED_OUTPUT, INTERNAL_ERROR
    error_message: Optional[str] = None
    execution_time_ms: float = 0.0


class BaseScanner(ABC):
    """Abstract interface for static security scanners."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the scanner engine."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Returns True if scanner executable / engine is installed and operational."""
        pass

    @abstractmethod
    def scan_file(
        self,
        file_path: str,
        relative_path: str,
        timeout_seconds: int = 15
    ) -> ScanExecutionResult:
        """Executes the scanner against an isolated file and returns structured results."""
        pass
