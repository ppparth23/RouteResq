"""Comprehensive tests for the VULNEX AI Secure Patch Validation Service.

Covers:
1. Success: Valid patch compilation, flaw eradication, zero regressions, and full check items.
2. Failure: Syntax errors, uneradicated target vulnerabilities, and introduced regressions.
3. Timeout handling: Controlled timeout catch and sanitized reporting without hanging.
4. Unavailable sandbox: Refusal to execute untrusted code directly on host when container sandbox is absent.
5. Malformed validation output: Graceful handling of unparseable check output.
6. Full REST API v1 integration (POST /remediations/{id}/validate and GET /validations/{id}).
"""

from unittest.mock import patch
import pytest

from app.security.sandbox import SandboxUnavailableError, check_syntax_safely
from app.services.validation_service import ValidationService
from app.storage.database import (
    get_remediation,
    init_db,
    save_finding,
    save_remediation,
    save_scan,
)


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


# ============================================================================
# 1. Pipeline Success Test
# ============================================================================

def test_validation_pipeline_success():
    """Verify that a valid patch cleanly compiles, eliminates the flaw, and produces structured checks."""
    rem_id = "rem_val_success_01"
    finding_id = "find_val_success_01"
    orig_code = (
        "import sqlite3\n"
        "def query_user(user_id):\n"
        "    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
    )
    patched_code = (
        "import sqlite3\n"
        "def query_user(user_id):\n"
        "    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
    )

    save_scan({
        "id": "scan_val_01",
        "source_type": "source_code",
        "target_name": "db.py",
        "status": "completed",
        "source_code": orig_code
    })

    save_finding({
        "id": finding_id,
        "scan_id": "scan_val_01",
        "title": "SQL Injection in cursor.execute",
        "severity": "high",
        "cwe_id": "CWE-89",
        "rule_id": "VULN-SQLI-001",
        "file_path": "db.py",
        "line_start": 3
    })

    save_remediation({
        "id": rem_id,
        "scan_id": "scan_val_01",
        "finding_id": finding_id,
        "status": "completed",
        "original_code": orig_code,
        "patched_code": patched_code,
        "unified_diff": "--- a/db.py\n+++ b/db.py\n",
        "validation_status": "UNVALIDATED"
    })

    result = ValidationService.validate_remediation(remediation_id=rem_id, strict_mode=True)

    # Core Result Assertions
    assert result.status == "completed"
    assert result.is_valid is True
    assert result.syntax_valid is True
    assert result.target_vulnerability_eradicated is True
    assert result.new_findings_count == 0
    assert result.findings_before >= 1
    assert result.findings_after == 0
    assert result.requires_human_review is True

    # Check Items Assertion
    check_names = [c.name for c in result.checks]
    assert "hash_comparison" in check_names
    assert "syntax_check" in check_names
    assert "static_security_rescan" in check_names
    assert "unit_tests" in check_names

    syntax_check = next(c for c in result.checks if c.name == "syntax_check")
    assert syntax_check.status == "passed"

    rescan_check = next(c for c in result.checks if c.name == "static_security_rescan")
    assert rescan_check.status == "passed"

    unit_test_check = next(c for c in result.checks if c.name == "unit_tests")
    assert unit_test_check.status == "not_available"


# ============================================================================
# 2. Pipeline Failure Tests
# ============================================================================

def test_validation_failure_syntax_error():
    """Verify that broken syntax fails the validation pipeline cleanly."""
    rem_id = "rem_val_syntax_fail"
    orig_code = "def calc(): return 1\n"
    broken_code = "def calc(): return (broken syntax (((\n"

    save_remediation({
        "id": rem_id,
        "scan_id": "scan_val_02",
        "finding_id": "find_val_02",
        "status": "completed",
        "original_code": orig_code,
        "patched_code": broken_code,
        "unified_diff": "--- a/source.py\n+++ b/source.py\n",
        "validation_status": "UNVALIDATED"
    })

    result = ValidationService.validate_remediation(remediation_id=rem_id)

    assert result.status == "failed"
    assert result.is_valid is False
    assert result.syntax_valid is False
    syntax_check = next(c for c in result.checks if c.name == "syntax_check")
    assert syntax_check.status == "failed"
    assert "syntax" in syntax_check.details.lower()


def test_validation_failure_uneradicated_flaw():
    """Verify that if the target flaw is still present structurally, validation fails."""
    rem_id = "rem_val_uneradicated"
    finding_id = "find_val_cmdi"
    orig_code = "import os\ndef run(cmd):\n    os.system(cmd)\n"
    # Patched code only changed variable name but kept os.system
    inadequate_patch = "import os\ndef run(target):\n    os.system(target)\n"

    save_finding({
        "id": finding_id,
        "scan_id": "scan_val_03",
        "title": "Command Injection",
        "severity": "high",
        "cwe_id": "CWE-78",
        "file_path": "cmd.py"
    })

    save_remediation({
        "id": rem_id,
        "scan_id": "scan_val_03",
        "finding_id": finding_id,
        "status": "completed",
        "original_code": orig_code,
        "patched_code": inadequate_patch,
        "unified_diff": "--- a/cmd.py\n+++ b/cmd.py\n",
        "validation_status": "UNVALIDATED"
    })

    result = ValidationService.validate_remediation(remediation_id=rem_id)

    assert result.status == "failed"
    assert result.is_valid is False
    assert result.target_vulnerability_eradicated is False
    rescan_check = next(c for c in result.checks if c.name == "static_security_rescan")
    assert rescan_check.status == "failed"


def test_validation_failure_regression_detected():
    """Verify that introducing a new vulnerability flags the patch as requires_review."""
    rem_id = "rem_val_regression"
    finding_id = "find_val_reg"
    orig_code = "def parse(data):\n    return str(data)\n"
    # Introduces arbitrary code execution via eval
    regression_code = "def parse(data):\n    return eval(data)\n"

    save_finding({
        "id": finding_id,
        "scan_id": "scan_val_04",
        "title": "Data formatting",
        "severity": "low",
        "cwe_id": "CWE-20",
        "file_path": "parse.py"
    })

    save_remediation({
        "id": rem_id,
        "scan_id": "scan_val_04",
        "finding_id": finding_id,
        "status": "completed",
        "original_code": orig_code,
        "patched_code": regression_code,
        "unified_diff": "--- a/parse.py\n+++ b/parse.py\n",
        "validation_status": "UNVALIDATED"
    })

    result = ValidationService.validate_remediation(remediation_id=rem_id)

    assert result.status == "requires_review"
    assert result.is_valid is False
    assert result.new_findings_count >= 1
    assert any(f.cwe_id == "CWE-95" for f in result.new_findings)


# ============================================================================
# 3. Unavailable Sandbox / Threat Model Test
# ============================================================================

def test_validation_unavailable_sandbox_refuses_host_execution():
    """
    Threat model invariant: When trusted dynamic tests are requested but no container
    sandbox is available, the server MUST NOT execute untrusted code on the host machine.
    """
    rem_id = "rem_val_sandbox_test"
    code = "import os\ndef ping(ip):\n    return subprocess.run(['ping', ip])\n"

    save_remediation({
        "id": rem_id,
        "scan_id": "scan_val_05",
        "finding_id": "find_val_05",
        "status": "completed",
        "original_code": code,
        "patched_code": code + "\n# safe comment",
        "unified_diff": "",
        "validation_status": "UNVALIDATED"
    })

    # Simulate container sandbox unavailable
    with patch("app.services.validation_service.is_secure_sandbox_available", return_value=(False, "Docker daemon not running")):
        result = ValidationService.validate_remediation(
            remediation_id=rem_id,
            strict_mode=True,
            trusted_test_command="pytest -v tests/"
        )

        assert result.status == "validation_unavailable"
        unit_test_check = next(c for c in result.checks if c.name == "unit_tests")
        assert unit_test_check.status == "not_available"
        assert "refused" in unit_test_check.details.lower()
        assert "host server" in unit_test_check.details.lower()


# ============================================================================
# 4. Timeout Handling Test
# ============================================================================

def test_validation_scanner_timeout_handling():
    """Verify that a scanner timeout is caught safely and does not crash the server."""
    rem_id = "rem_val_timeout"
    code = "def long_loop(): pass\n"

    save_remediation({
        "id": rem_id,
        "scan_id": "scan_val_06",
        "finding_id": "find_val_06",
        "status": "completed",
        "original_code": code,
        "patched_code": code,
        "unified_diff": "",
        "validation_status": "UNVALIDATED"
    })

    with patch("app.services.validation_service.ScannerService.scan_code", side_effect=TimeoutError("Scanner timed out after 10s")):
        result = ValidationService.validate_remediation(remediation_id=rem_id)

        assert result.status == "failed"
        rescan_check = next(c for c in result.checks if c.name == "static_security_rescan")
        assert rescan_check.status == "error"
        assert "timed out" in rescan_check.details.lower()


# ============================================================================
# 5. Malformed Validation Output Test
# ============================================================================

def test_validation_malformed_scanner_output():
    """Verify that corrupt or malformed scanner output is caught as an error check without uncaught crashes."""
    rem_id = "rem_val_malformed"
    code = "def check(): pass\n"

    save_remediation({
        "id": rem_id,
        "scan_id": "scan_val_07",
        "finding_id": "find_val_07",
        "status": "completed",
        "original_code": code,
        "patched_code": code + "\n# note",
        "unified_diff": "",
        "validation_status": "UNVALIDATED"
    })

    with patch("app.services.validation_service.FindingNormalizer.normalize", side_effect=ValueError("Corrupt JSON payload")):
        result = ValidationService.validate_remediation(remediation_id=rem_id)

        assert result.status == "failed"
        rescan_check = next(c for c in result.checks if c.name == "static_security_rescan")
        assert rescan_check.status == "error"
        assert "corrupt" in rescan_check.details.lower() or "error" in rescan_check.details.lower()


# ============================================================================
# 6. REST API v1 Integration Endpoints Test
# ============================================================================

def test_v1_api_validation_endpoints(client):
    """Test full HTTP POST /remediations/{id}/validate and GET /validations/{id} flow."""
    rem_id = "rem_v1_api_val"
    finding_id = "find_v1_api_val"
    orig_code = "import os\ndef ping(ip): os.system('ping ' + ip)\n"
    patched_code = "import subprocess, shlex\ndef ping(ip): subprocess.run(shlex.split('ping ' + ip), shell=False, check=True)\n"

    save_finding({
        "id": finding_id,
        "scan_id": "scan_v1_08",
        "title": "Command Injection in ping",
        "severity": "high",
        "cwe_id": "CWE-78",
        "file_path": "net.py"
    })

    save_remediation({
        "id": rem_id,
        "scan_id": "scan_v1_08",
        "finding_id": finding_id,
        "status": "completed",
        "original_code": orig_code,
        "patched_code": patched_code,
        "unified_diff": "--- a/net.py\n+++ b/net.py\n",
        "validation_status": "UNVALIDATED"
    })

    # 1. POST /api/v1/remediations/{id}/validate
    val_post_resp = client.post(f"/api/v1/remediations/{rem_id}/validate", json={
        "strict_mode": True
    })
    assert val_post_resp.status_code == 201
    val_data = val_post_resp.json()
    val_id = val_data["id"]
    assert val_data["remediation_id"] == rem_id
    assert val_data["status"] == "completed"
    assert val_data["is_valid"] is True
    assert val_data["syntax_valid"] is True
    assert val_data["target_vulnerability_eradicated"] is True
    assert len(val_data["checks"]) >= 3
    assert val_data["requires_human_review"] is True
    assert "summary" in val_data

    # Verify remediation record in database was updated to VALIDATED
    rem_updated = get_remediation(rem_id)
    assert rem_updated["validation_status"] == "VALIDATED"

    # 2. GET /api/v1/validations/{val_id}
    val_get_resp = client.get(f"/api/v1/validations/{val_id}")
    assert val_get_resp.status_code == 200
    get_data = val_get_resp.json()
    assert get_data["id"] == val_id
    assert get_data["remediation_id"] == rem_id
    assert get_data["status"] == "completed"
    assert get_data["is_valid"] is True
    assert len(get_data["checks"]) >= 3


# ============================================================================
# 7. Legacy Compatibility Tests
# ============================================================================

def test_legacy_validate_successful_patch(client):
    orig = "import os\ndef ping(ip):\n    os.system('ping ' + ip)\n"
    patched = "import subprocess\nimport shlex\ndef ping(ip):\n    subprocess.run(shlex.split('ping ' + ip), shell=False, check=True)\n"

    payload = {
        "original_code": orig,
        "patched_code": patched,
        "target_cwe_id": "CWE-78",
        "file_name": "network.py"
    }
    response = client.post("/api/validation/validate-patch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_valid"] is True
    assert data["syntax_valid"] is True
    assert data["target_vulnerability_eradicated"] is True
    assert data["new_findings_count"] == 0


def test_legacy_validate_patch_syntax_error(client):
    orig = "import os\ndef ping(ip):\n    os.system('ping ' + ip)\n"
    broken_patch = "import subprocess\ndef ping(ip):\n    subprocess.run(broken syntax invalid (((\n"

    payload = {
        "original_code": orig,
        "patched_code": broken_patch,
        "target_cwe_id": "CWE-78"
    }
    response = client.post("/api/validation/validate-patch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_valid"] is False
    assert data["syntax_valid"] is False


def test_legacy_validate_patch_introduces_regression(client):
    orig = "def hash_val(val):\n    return str(val)\n"
    regression_patch = "def hash_val(val):\n    return eval(val)\n"

    payload = {
        "original_code": orig,
        "patched_code": regression_patch,
        "target_cwe_id": "CWE-89"
    }
    response = client.post("/api/validation/validate-patch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_valid"] is False
    assert data["new_findings_count"] >= 1
    assert any(f["cwe_id"] == "CWE-95" for f in data["new_findings"])
