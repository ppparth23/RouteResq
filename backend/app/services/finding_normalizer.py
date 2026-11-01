"""Normalizer and classifier for vulnerability findings."""

import uuid
from datetime import datetime, timezone
from typing import List, Tuple
from app.schemas.v1 import Finding, FindingEvidence, ScanSummary
from app.services.scanner import RawFinding

CATEGORY_MAP = {
    "CWE-89": "SQL Injection",
    "CWE-78": "Command Injection",
    "CWE-502": "Insecure Deserialization",
    "CWE-798": "Hardcoded Secrets",
    "CWE-327": "Cryptography",
    "CWE-95": "Dynamic Code Evaluation",
    "CWE-22": "Path Traversal",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-942": "CORS Security",
    "CWE-79": "Cross-Site Scripting"
}

IMPACT_MAP = {
    "CWE-89": "Unauthorized database read/write, privilege escalation, authentication bypass.",
    "CWE-78": "Arbitrary OS command execution with application privileges.",
    "CWE-502": "Arbitrary code execution via object deserialization.",
    "CWE-798": "Exposure of sensitive credentials enabling unauthorized API and system access.",
    "CWE-327": "Cryptographic collisions leading to hash reversal or signature forging.",
    "CWE-95": "Arbitrary code execution inside application interpreter.",
    "CWE-22": "Unauthorized read or overwrite of sensitive server files.",
    "CWE-918": "Internal network traversal and cloud metadata extraction.",
    "CWE-942": "Unauthorized cross-origin read of sensitive user data.",
    "CWE-79": "Execution of attacker-controlled script in user's browser session."
}


class FindingNormalizer:
    """Normalizes raw scanner findings into standardized API schemas and summaries."""

    @staticmethod
    def normalize(
        raw_findings: List[RawFinding],
        scan_id: str
    ) -> Tuple[List[Finding], ScanSummary]:
        normalized: List[Finding] = []
        summary = ScanSummary()

        for f in raw_findings:
            finding_id = f"find_{uuid.uuid4().hex[:12]}"
            severity = (f.severity or "medium").lower()

            # Ensure severity is valid
            if severity not in ("critical", "high", "medium", "low", "info", "unknown"):
                severity = "medium"

            # Update summary counts
            summary.total += 1
            if severity == "critical":
                summary.critical += 1
            elif severity == "high":
                summary.high += 1
            elif severity == "medium":
                summary.medium += 1
            elif severity == "low":
                summary.low += 1
            elif severity == "info":
                summary.info += 1
            else:
                summary.unknown += 1

            category = CATEGORY_MAP.get(f.cwe_id, "Application Security")
            impact = IMPACT_MAP.get(f.cwe_id, "Potential security degradation depending on operational context.")

            evidence = FindingEvidence(
                snippet=f.code_snippet,
                ast_rule=f.rule_id,
                pattern=f.rule_id
            )

            finding = Finding(
                id=finding_id,
                scan_id=scan_id,
                rule_id=f.rule_id,
                title=f.title,
                severity=severity,
                category=category,
                cwe_id=f.cwe_id,
                file_path=f.file_path,
                line_start=f.line_number,
                line_end=f.line_number,
                line_number=f.line_number,
                code_snippet=f.code_snippet,
                evidence=evidence,
                description=f.description,
                impact=impact,
                recommendation=f.recommendation,
                source="ast_scanner" if "AST" in str(type(f)) or f.rule_id.startswith("VULN-") else "regex_scanner",
                confidence="high",
                status="open"
            )
            normalized.append(finding)

        return normalized, summary
