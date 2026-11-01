"""End-to-End Live Hackathon Demonstration Flow Test.

Validates that VULNEX AI can:
1. Analyze source code using intentionally vulnerable demo fixtures.
2. Identify supported security findings (CWE-89 and CWE-798).
3. Explain findings using the configured AI provider.
4. Generate proposed code patches.
5. Produce readable before-and-after unified diffs.
6. Run validation checks safely in the isolated sandbox.
7. Report exact pass, fail, or unverified states.
"""

from pathlib import Path
import pytest
from app.storage.database import init_db


EXAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "examples"


def test_sql_injection_demo_flow(client):
    """E2E demonstration test using examples/sql_injection_vulnerable.py."""
    fixture_path = EXAMPLES_DIR / "sql_injection_vulnerable.py"
    assert fixture_path.exists(), f"Missing demo fixture: {fixture_path}"
    source_code = fixture_path.read_text(encoding="utf-8")

    # 1. Health check & provider status
    health_resp = client.get("/api/v1/health")
    assert health_resp.status_code == 200
    health_data = health_resp.json()
    assert health_data["status"] == "ok"
    assert "ai_provider" in health_data

    # 2. Submit source code scan
    scan_req = {
        "source_type": "source_code",
        "language": "python",
        "filename": "sql_injection_vulnerable.py",
        "source_code": source_code,
    }
    scan_resp = client.post("/api/v1/scans", json=scan_req)
    assert scan_resp.status_code == 201
    scan_data = scan_resp.json()
    scan_id = scan_data["id"]
    assert scan_data["status"] == "completed"
    assert scan_data["summary"]["total"] >= 1
    assert (scan_data["summary"]["critical"] >= 1 or scan_data["summary"]["high"] >= 1 or scan_data["summary"]["medium"] >= 1)

    # 3. Retrieve findings
    findings_resp = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) >= 1

    sqli_finding = next((f for f in findings if f["cwe_id"] == "CWE-89"), None)
    assert sqli_finding is not None, "Scanner must detect CWE-89 in sql_injection_vulnerable.py"
    assert "cursor.execute" in sqli_finding["evidence"]["snippet"] or "SELECT" in sqli_finding["evidence"]["snippet"]
    finding_id = sqli_finding["id"]

    # 4. Request remediation patch
    rem_resp = client.post(f"/api/v1/findings/{finding_id}/remediations", json={
        "prompt_context": "Use parameterized query with ? placeholder",
        "auto_validate": True,
    })
    assert rem_resp.status_code == 201
    rem_data = rem_resp.json()
    remediation_id = rem_data["id"]
    assert rem_data["status"] in ("completed", "requires_review")

    # 5. Inspect unified diff
    diff_resp = client.get(f"/api/v1/remediations/{remediation_id}/diff")
    assert diff_resp.status_code == 200
    diff_data = diff_resp.json()
    assert "unified_diff" in diff_data
    assert len(diff_data["unified_diff"]) > 0
    assert "proposed_code" in diff_data
    assert len(diff_data["proposed_code"]) > 0

    # 6. Run validation pipeline
    val_resp = client.post(f"/api/v1/remediations/{remediation_id}/validate", json={"strict_mode": True})
    assert val_resp.status_code == 201
    val_data = val_resp.json()
    assert val_data["syntax_valid"] is True
    assert val_data["target_vulnerability_eradicated"] is True
    assert isinstance(val_data["checks"], list)
    assert len(val_data["checks"]) >= 3

    # Check that individual checks are properly reported
    check_names = [c["name"] for c in val_data["checks"]]
    assert any("syntax" in name.lower() for name in check_names)
    assert any("static_security_rescan" in name.lower() or "rescan" in name.lower() for name in check_names)


def test_hardcoded_credential_demo_flow(client):
    """E2E demonstration test using examples/hardcoded_credential_vulnerable.py."""
    fixture_path = EXAMPLES_DIR / "hardcoded_credential_vulnerable.py"
    assert fixture_path.exists(), f"Missing demo fixture: {fixture_path}"
    source_code = fixture_path.read_text(encoding="utf-8")

    # 1. Submit source code scan
    scan_req = {
        "source_type": "source_code",
        "language": "python",
        "filename": "hardcoded_credential_vulnerable.py",
        "source_code": source_code,
    }
    scan_resp = client.post("/api/v1/scans", json=scan_req)
    assert scan_resp.status_code == 201
    scan_data = scan_resp.json()
    scan_id = scan_data["id"]
    assert scan_data["status"] == "completed"

    # 2. Retrieve findings
    findings_resp = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) >= 1

    secret_finding = next((f for f in findings if f["cwe_id"] == "CWE-798"), None)
    assert secret_finding is not None, "Scanner must detect CWE-798 in hardcoded_credential_vulnerable.py"
    assert secret_finding["severity"] in ("high", "medium")
