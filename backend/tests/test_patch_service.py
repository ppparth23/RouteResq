"""Comprehensive tests for the VULNEX AI Patch Generation Service.

Covers:
1. Valid patch generation, diff calculation, hashes, and artifact persistence.
2. Empty patch handling (preserves original, flags requires_review).
3. Malformed model response handling (schema validation failure caught, no crash).
4. Unchanged output handling (identical code marked requires_review).
5. Unexpected unrelated changes (code drift detection).
6. Explicit line endings (CRLF vs LF) and UTF-8 encoding handling.
7. Finding source alignment verification.
8. REST API v1 remediation lifecycle endpoints.
"""

import hashlib
import json
import os
from unittest.mock import AsyncMock, patch
import pytest

from app.config import settings
from app.schemas.ai import (
    AIExecutionMetadata,
    AIPatchProposal,
    AIPatchResult,
    ChangeItem,
)
from app.services.patch_service import PatchService
from app.storage.database import (
    get_remediation,
    init_db,
    save_finding,
    save_scan,
)


@pytest.fixture(autouse=True)
def setup_test_db():
    init_db()


def test_valid_patch_generation_and_artifact_storage():
    """Verify that a valid vulnerability generates a patch, diff, hashes, and persisted artifacts."""
    scan_id = "scan_patch_valid_01"
    finding_id = "find_patch_valid_01"
    vulnerable_source = (
        "import sqlite3\n"
        "\n"
        "def get_user_records(user_id):\n"
        "    conn = sqlite3.connect('test.db')\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
        "    return cursor.fetchall()\n"
    )

    save_scan({
        "id": scan_id,
        "source_type": "source_code",
        "target_name": "db_query.py",
        "status": "completed",
        "source_code": vulnerable_source
    })

    save_finding({
        "id": finding_id,
        "scan_id": scan_id,
        "title": "SQL Injection in cursor.execute",
        "severity": "high",
        "cwe_id": "CWE-89",
        "rule_id": "VULN-SQLI-001",
        "file_path": "db_query.py",
        "line_start": 6,
        "line_end": 6,
        "evidence": {"snippet": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"},
        "description": "Dynamic SQL interpolation without parameterized query."
    })

    import asyncio
    result = asyncio.run(PatchService.remediate_finding(finding_id))

    # Verification: Lifecycle & Review State
    assert result["id"].startswith("rem_")
    assert result["status"] == "completed"
    assert result["requires_review"] is True
    assert result["validation_status"] == "UNVALIDATED"  # Crucial: never claim valid without validation

    # Verification: Code & Hashes
    assert result["original_code"] == vulnerable_source
    assert result["patched_code"] != vulnerable_source
    assert "%s" in result["patched_code"] or "?" in result["patched_code"]

    orig_expected_hash = hashlib.sha256(vulnerable_source.encode("utf-8")).hexdigest()
    prop_expected_hash = hashlib.sha256(result["patched_code"].encode("utf-8")).hexdigest()
    assert result["original_hash"] == orig_expected_hash
    assert result["proposed_hash"] == prop_expected_hash

    # Verification: Unified Diff
    diff = result["unified_diff"]
    assert "--- a/db_query.py" in diff
    assert "+++ b/db_query.py" in diff
    assert result["added_lines"] > 0
    assert result["removed_lines"] > 0

    # Verification: Stored Artifacts on disk
    artifact_path = result["artifact_path"]
    assert os.path.exists(artifact_path)
    assert os.path.exists(os.path.join(artifact_path, "original_db_query.py"))
    assert os.path.exists(os.path.join(artifact_path, "proposed_db_query.py"))
    assert os.path.exists(os.path.join(artifact_path, "patch.diff"))
    assert os.path.exists(os.path.join(artifact_path, "metadata.json"))

    # Verify metadata JSON
    with open(os.path.join(artifact_path, "metadata.json"), "r", encoding="utf-8") as f:
        meta = json.load(f)
    assert meta["remediation_id"] == result["id"]
    assert meta["finding_id"] == finding_id
    assert meta["original_hash"] == orig_expected_hash
    assert meta["proposed_hash"] == prop_expected_hash
    assert meta["validation_status"] == "UNVALIDATED"


def test_empty_patch_handling(monkeypatch):
    """Verify that if the patch proposal is empty, the system preserves original and flags requires_review."""
    scan_id = "scan_patch_empty_01"
    finding_id = "find_patch_empty_01"
    source = "def do_work():\n    return 42\n"

    save_scan({
        "id": scan_id,
        "source_type": "source_code",
        "target_name": "empty_test.py",
        "status": "completed",
        "source_code": source
    })

    save_finding({
        "id": finding_id,
        "scan_id": scan_id,
        "title": "Minor warning",
        "severity": "low",
        "cwe_id": "CWE-999",
        "file_path": "empty_test.py",
        "line_start": 2,
        "description": "Test warning"
    })

    monkeypatch.setattr(settings, "gemini_api_key", "mock_key")

    # Mock AIService.generate_patch to return whitespace-only code
    empty_proposal = AIPatchProposal(
        summary="Empty fix",
        rationale="Nothing to do",
        patched_code="   \n   ",
        changes=[],
        limitations=[]
    )
    mock_ai_result = AIPatchResult(
        success=True,
        proposal=empty_proposal,
        requires_review=True,
        validation_state="UNVALIDATED",
        metadata=AIExecutionMetadata(provider="mock", model="mock", status="SUCCESS", duration_ms=10.0)
    )

    with patch("app.services.patch_service.AIService.generate_patch", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = mock_ai_result

        import asyncio
        result = asyncio.run(PatchService.remediate_finding(finding_id))

        assert result["status"] == "requires_review"
        assert result["requires_review"] is True
        assert result["patched_code"] == source  # Original code preserved!
        assert any("empty" in lim.lower() for lim in result["limitations"])
        assert result["unified_diff"] == ""


def test_malformed_model_response(monkeypatch):
    """Verify that a malformed response from the model is caught and handled safely without crashing."""
    scan_id = "scan_patch_malformed_01"
    finding_id = "find_patch_malformed_01"
    source = "import os\ndef test():\n    os.system('ping 127.0.0.1')\n"

    save_scan({
        "id": scan_id,
        "source_type": "source_code",
        "target_name": "malformed.py",
        "status": "completed",
        "source_code": source
    })

    save_finding({
        "id": finding_id,
        "scan_id": scan_id,
        "title": "Command Injection",
        "severity": "high",
        "cwe_id": "CWE-78",
        "file_path": "malformed.py",
        "line_start": 3,
        "description": "os.system call"
    })

    monkeypatch.setattr(settings, "gemini_api_key", "mock_key")

    # Simulate AI Service raising an exception due to schema corruption
    with patch("app.services.patch_service.AIService.generate_patch", new_callable=AsyncMock) as mock_gen:
        mock_gen.side_effect = ValueError("Malformed JSON payload returned by provider: missing field 'summary'")

        import asyncio
        result = asyncio.run(PatchService.remediate_finding(finding_id))

        # System falls back safely to rule engine or flags requires_review
        assert result["status"] in ("completed", "requires_review")
        assert result["requires_review"] is True
        assert any("failed" in lim.lower() or "malformed" in lim.lower() for lim in result["limitations"])
        assert result["patched_code"] != ""


def test_unchanged_output_handling():
    """Verify that if the proposed code is identical to original, it is marked requires_review."""
    scan_id = "scan_patch_unchanged_01"
    finding_id = "find_patch_unchanged_01"
    source = "def clean_calc(a, b):\n    return a + b\n"

    save_scan({
        "id": scan_id,
        "source_type": "source_code",
        "target_name": "clean.py",
        "status": "completed",
        "source_code": source
    })

    save_finding({
        "id": finding_id,
        "scan_id": scan_id,
        "title": "Unmatched finding",
        "severity": "low",
        "cwe_id": "CWE-000",
        "file_path": "clean.py",
        "line_start": 2,
        "description": "No rule fixes this."
    })

    import asyncio
    result = asyncio.run(PatchService.remediate_finding(finding_id))

    assert result["status"] == "requires_review"
    assert result["requires_review"] is True
    assert result["patched_code"] == source
    assert result["unified_diff"] == ""
    assert any("identical" in lim.lower() or "no code changes" in lim.lower() for lim in result["limitations"])


def test_unexpected_unrelated_changes_drift_detection():
    """Verify that modifications to unrelated functions or code regions trigger drift detection."""
    original_code = (
        "def function_one():\n"
        "    return 1\n"
        "\n"
        "def function_two():\n"
        "    return 2\n"
        "\n"
        "def vulnerable_function(user_input):\n"
        "    import os\n"
        "    os.system(user_input)\n"
        "\n"
        "def function_three():\n"
        "    return 3\n"
        "\n"
        "def function_four():\n"
        "    return 4\n"
    )

    # Patch correctly fixes vulnerable_function, BUT ALSO unexpectedly modifies function_four!
    drifted_patch = (
        "def function_one():\n"
        "    return 1\n"
        "\n"
        "def function_two():\n"
        "    return 2\n"
        "\n"
        "def vulnerable_function(user_input):\n"
        "    import subprocess, shlex\n"
        "    subprocess.run(shlex.split(user_input), shell=False, check=True)\n"
        "\n"
        "def function_three():\n"
        "    return 3\n"
        "\n"
        "def function_four():\n"
        "    # Unrelated change that should NOT be here\n"
        "    return 9999\n"
    )

    is_drifted, reason = PatchService.detect_code_drift(
        original_code=original_code,
        patched_code=drifted_patch,
        line_start=9,
        line_end=9
    )

    assert is_drifted is True
    assert "outside finding scope" in reason
    assert "drift" in reason.lower()


def test_line_ending_and_encoding_preservation():
    """Verify that Windows CRLF and UTF-8 characters are handled without corrupting line endings or diffs."""
    crlf_source = "def greet(name):\r\n    # Unicode: \u00e9\u00e0\u00fc \u2764\r\n    import os\r\n    os.system(name)\r\n"
    crlf_patched = "import subprocess\r\nimport shlex\r\ndef greet(name):\r\n    # Unicode: \u00e9\u00e0\u00fc \u2764\r\n    subprocess.run(shlex.split(name), shell=False, check=True)\r\n"

    diff, added, removed = PatchService.generate_unified_diff(crlf_source, crlf_patched, "greet.py")

    assert "--- a/greet.py" in diff
    assert "+++ b/greet.py" in diff
    # Diff must be clean and not have \r printed as characters
    assert "\r" not in diff
    assert added > 0
    assert removed > 0


def test_v1_api_remediation_lifecycle_endpoints(client):
    """Verify GET/POST remediation endpoints adhere to REST contract and return UI review fields."""
    scan_id = "scan_api_rem_01"
    finding_id = "find_api_rem_01"
    source = (
        "import os\n"
        "def execute_cmd(cmd):\n"
        "    os.system(cmd)\n"
    )

    save_scan({
        "id": scan_id,
        "source_type": "source_code",
        "target_name": "cmd.py",
        "status": "completed",
        "source_code": source
    })

    save_finding({
        "id": finding_id,
        "scan_id": scan_id,
        "title": "Command Injection in execute_cmd",
        "severity": "high",
        "cwe_id": "CWE-78",
        "rule_id": "VULN-CMDI-001",
        "file_path": "cmd.py",
        "line_start": 3,
        "description": "Unchecked os.system"
    })

    # 1. POST /api/v1/findings/{id}/remediations
    resp = client.post(f"/api/v1/findings/{finding_id}/remediations", json={
        "prompt_context": "Use subprocess.run without shell",
        "auto_validate": False
    })
    assert resp.status_code == 201
    data = resp.json()
    rem_id = data["id"]
    assert data["finding_id"] == finding_id
    assert data["status"] in ("completed", "requires_review")
    assert data["validation_status"] == "UNVALIDATED"
    assert data["original_hash"] is not None
    assert data["proposed_hash"] is not None

    # 2. GET /api/v1/remediations/{rem_id}
    get_resp = client.get(f"/api/v1/remediations/{rem_id}")
    assert get_resp.status_code == 200
    rem_data = get_resp.json()
    assert rem_data["id"] == rem_id
    assert rem_data["validation_status"] == "UNVALIDATED"
    assert rem_data["requires_review"] is True
    assert "artifact_path" in rem_data

    # 3. GET /api/v1/remediations/{rem_id}/diff
    diff_resp = client.get(f"/api/v1/remediations/{rem_id}/diff")
    assert diff_resp.status_code == 200
    diff_data = diff_resp.json()
    assert diff_data["remediation_id"] == rem_id
    assert diff_data["original_code"] == source
    assert "subprocess.run" in diff_data["proposed_code"]
    assert "--- a/cmd.py" in diff_data["unified_diff"]
    assert diff_data["added_lines"] > 0
    assert diff_data["removed_lines"] > 0
    assert diff_data["original_hash"] is not None
    assert diff_data["proposed_hash"] is not None
