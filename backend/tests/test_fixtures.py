"""Tests verifying scanner accuracy against sample fixtures."""

from pathlib import Path
from app.services.scanner import ScannerService


def test_vulnerable_app_fixture_detection():
    fixture_path = Path(__file__).resolve().parent.parent.parent / "fixtures" / "vulnerable_app.py"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    findings = ScannerService.scan_code(content, file_path="vulnerable_app.py")
    cwe_set = {f.cwe_id for f in findings}

    assert "CWE-89" in cwe_set   # SQL Injection
    assert "CWE-78" in cwe_set   # Command Injection
    assert "CWE-502" in cwe_set  # Insecure Deserialization
    assert "CWE-327" in cwe_set  # Broken Crypto MD5
    assert "CWE-798" in cwe_set  # Hardcoded Secret


def test_clean_app_fixture_passes_without_findings():
    fixture_path = Path(__file__).resolve().parent.parent.parent / "fixtures" / "clean_app.py"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    findings = ScannerService.scan_code(content, file_path="clean_app.py")
    assert len(findings) == 0
