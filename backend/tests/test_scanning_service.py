"""Unit and integration tests for Vulnex AI Static Security Scanning Service."""

import os
from pathlib import Path
import pytest
from fastapi import HTTPException
from app.services.scanners.bandit_scanner import BanditScanner
from app.services.scanners.base import redact_secrets
from app.services.scanners.pipeline import ScanningPipeline
from app.services.scanners.semgrep_scanner import SemgrepScanner

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures"


def read_fixture(filename: str) -> str:
    path = FIXTURES_DIR / filename
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# -----------------------------------------------------------------------------
# Bandit Scanner Tests
# -----------------------------------------------------------------------------

def test_bandit_scanner_availability():
    scanner = BanditScanner()
    assert scanner.name == "bandit"
    assert scanner.is_available() is True


def test_bandit_scan_vulnerable_fixture():
    code = read_fixture("vulnerable_app.py")
    pipeline = ScanningPipeline(enable_bandit=True, enable_semgrep=False)
    response, findings = pipeline.execute_scan(code, filename="vulnerable_app.py")

    assert response.status == "completed"
    assert len(findings) > 0

    cwe_set = {f.cwe_id for f in findings}
    rule_set = {f.rule_id for f in findings}

    # Verify Bandit findings mapped correctly
    assert any("CWE-78" in cwe or "B605" in rule_set for cwe in cwe_set)
    assert any("CWE-89" in cwe or "B608" in rule_set for cwe in cwe_set)
    assert any("CWE-502" in cwe or "B301" in rule_set or "B403" in rule_set for cwe in cwe_set)


# -----------------------------------------------------------------------------
# Semgrep Scanner Tests
# -----------------------------------------------------------------------------

def test_semgrep_scanner_availability():
    scanner = SemgrepScanner()
    assert scanner.name == "semgrep"
    assert scanner.is_available() is True


def test_semgrep_scan_command_injection():
    code = read_fixture("command_injection_pattern.py")
    scanner = SemgrepScanner()
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", encoding="utf-8", delete=False) as tf:
        tf.write(code)
        tf_path = tf.name

    try:
        res = scanner.scan_file(tf_path, relative_path="command_injection_pattern.py")
        assert res.success is True
        assert len(res.findings) >= 1
        rule_ids = [f.rule_id for f in res.findings]
        assert any("os-system" in r or "subprocess-shell" in r for r in rule_ids)
    finally:
        if os.path.exists(tf_path):
            os.remove(tf_path)


# -----------------------------------------------------------------------------
# Paired Pattern vs Secure Example Tests
# -----------------------------------------------------------------------------

def test_sql_injection_pattern_vs_secure():
    pipeline = ScanningPipeline()
    vuln_code = read_fixture("sql_injection_pattern.py")
    sec_code = read_fixture("sql_injection_secure.py")

    # Vulnerable triggers finding
    _, vuln_findings = pipeline.execute_scan(vuln_code, filename="sql_injection_pattern.py")
    assert any(f.cwe_id == "CWE-89" for f in vuln_findings)

    # Secure example does NOT trigger finding
    _, sec_findings = pipeline.execute_scan(sec_code, filename="sql_injection_secure.py")
    assert not any(f.cwe_id == "CWE-89" for f in sec_findings)


def test_command_injection_pattern_vs_secure():
    pipeline = ScanningPipeline()
    vuln_code = read_fixture("command_injection_pattern.py")
    sec_code = read_fixture("command_injection_secure.py")

    _, vuln_findings = pipeline.execute_scan(vuln_code, filename="command_injection_pattern.py")
    assert any(f.cwe_id == "CWE-78" for f in vuln_findings)

    _, sec_findings = pipeline.execute_scan(sec_code, filename="command_injection_secure.py")
    assert not any(f.cwe_id == "CWE-78" for f in sec_findings)


def test_insecure_deserialization_pattern_vs_secure():
    pipeline = ScanningPipeline()
    vuln_code = read_fixture("insecure_deserialization_pattern.py")
    sec_code = read_fixture("insecure_deserialization_secure.py")

    _, vuln_findings = pipeline.execute_scan(vuln_code, filename="insecure_deserialization_pattern.py")
    assert any(f.cwe_id == "CWE-502" for f in vuln_findings)

    _, sec_findings = pipeline.execute_scan(sec_code, filename="insecure_deserialization_secure.py")
    assert not any(f.cwe_id == "CWE-502" for f in sec_findings)


# -----------------------------------------------------------------------------
# Evidence & Redaction Tests
# -----------------------------------------------------------------------------

def test_secret_redaction_in_evidence():
    raw_leak = 'api_key = "AIzaSyD-CONFIDENTIAL-TOKEN-9999"\njwt_secret = "secret_key_123456"'
    redacted = redact_secrets(raw_leak)
    assert "AIzaSyD-CONFIDENTIAL-TOKEN-9999" not in redacted
    assert "secret_key_123456" not in redacted
    assert "[REDACTED" in redacted


# -----------------------------------------------------------------------------
# Failure Handling Tests
# -----------------------------------------------------------------------------

def test_unsupported_language_rejection():
    pipeline = ScanningPipeline()
    with pytest.raises(HTTPException) as exc:
        pipeline.execute_scan("puts 'hello'", filename="test.rb", language="ruby")
    assert exc.value.status_code == 400
    assert "Unsupported language 'ruby'" in exc.value.detail


def test_empty_source_rejection():
    pipeline = ScanningPipeline()
    with pytest.raises(HTTPException) as exc:
        pipeline.execute_scan("", filename="empty.py", language="python")
    assert exc.value.status_code == 400


def test_timeout_handling():
    # Test scanner timeout gracefully without crashing
    scanner = BanditScanner()
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", encoding="utf-8", delete=False) as tf:
        tf.write("x = 1\n")
        tf_path = tf.name

    try:
        # Run with 0-second timeout to trigger timeout handler
        res = scanner.scan_file(tf_path, relative_path="test.py", timeout_seconds=0)
        assert res.success is False
        assert res.error_type == "TIMEOUT"
    finally:
        if os.path.exists(tf_path):
            os.remove(tf_path)


def test_clean_code_produces_zero_findings_no_fabrication():
    """Verify clean code does not fabricate security findings."""
    pipeline = ScanningPipeline()
    clean_code = "def safe_add(a: int, b: int) -> int:\n    return a + b\n"
    response, findings = pipeline.execute_scan(clean_code, filename="safe_math.py", language="python")

    assert response.status == "completed"
    assert response.summary.total == 0
    assert response.summary.critical == 0
    assert response.summary.high == 0
    assert response.summary.medium == 0
    assert len(findings) == 0


def test_malformed_scanner_output_handling():
    """Verify that corrupt or malformed scanner output produces MALFORMED_OUTPUT without fabricated findings."""
    from unittest.mock import patch, MagicMock
    scanner = BanditScanner()

    mock_proc = MagicMock()
    mock_proc.stdout = "NOT_VALID_JSON{abc: 123"
    mock_proc.stderr = ""
    mock_proc.returncode = 1

    with patch("subprocess.run", return_value=mock_proc):
        res = scanner.scan_file("dummy.py", "dummy.py")
        assert res.success is False
        assert res.error_type == "MALFORMED_OUTPUT"
        assert len(res.findings) == 0

