"""Integration tests for the Vulnex AI v1 REST API Contract."""

def test_v1_health_endpoint(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "vulnex-api"
    assert data["version"] == "1.0.0"
    assert "ai_provider" in data
    assert "configured" in data["ai_provider"]
    assert "available" in data["ai_provider"]
    assert "tested" in data["ai_provider"]
    # Check that secrets are not exposed
    assert "api_key" not in data["ai_provider"]
    assert "token" not in data["ai_provider"]


def test_v1_scan_source_code_and_lifecycle(client):
    vulnerable_code = """import os
def execute(cmd):
    os.system(cmd)
"""
    req_payload = {
        "source_type": "source_code",
        "language": "python",
        "filename": "vuln_command.py",
        "source_code": vulnerable_code
    }
    # 1. POST /api/v1/scans
    scan_resp = client.post("/api/v1/scans", json=req_payload)
    assert scan_resp.status_code == 201
    scan_data = scan_resp.json()
    assert "id" in scan_data
    scan_id = scan_data["id"]
    assert scan_data["status"] == "completed"
    assert scan_data["summary"]["total"] >= 1
    assert (scan_data["summary"]["critical"] >= 1 or scan_data["summary"]["high"] >= 1)

    # 2. GET /api/v1/scans/{scan_id}
    get_scan = client.get(f"/api/v1/scans/{scan_id}")
    assert get_scan.status_code == 200
    assert get_scan.json()["id"] == scan_id

    # 3. GET /api/v1/scans/{scan_id}/findings
    findings_resp = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert isinstance(findings, list)
    assert len(findings) >= 1

    finding = findings[0]
    finding_id = finding["id"]
    assert finding["scan_id"] == scan_id
    assert finding["cwe_id"] == "CWE-78"
    assert finding["severity"] in ("critical", "high", "medium", "low", "info", "unknown")
    assert finding["evidence"]["snippet"] is not None
    assert finding["source"] in ("bandit", "semgrep", "ast_scanner", "regex_scanner")

    # 4. GET /api/v1/findings/{finding_id}
    single_finding = client.get(f"/api/v1/findings/{finding_id}")
    assert single_finding.status_code == 200
    assert single_finding.json()["id"] == finding_id

    # 5. POST /api/v1/findings/{finding_id}/remediations
    rem_payload = {
        "prompt_context": "Remediate with subprocess",
        "auto_validate": True
    }
    rem_resp = client.post(f"/api/v1/findings/{finding_id}/remediations", json=rem_payload)
    assert rem_resp.status_code == 201
    rem_data = rem_resp.json()
    assert "id" in rem_data
    remediation_id = rem_data["id"]
    assert rem_data["status"] in ("completed", "requires_review", "queued")

    # 6. GET /api/v1/remediations/{remediation_id}
    get_rem = client.get(f"/api/v1/remediations/{remediation_id}")
    assert get_rem.status_code == 200
    assert get_rem.json()["id"] == remediation_id

    # 7. GET /api/v1/remediations/{remediation_id}/diff
    diff_resp = client.get(f"/api/v1/remediations/{remediation_id}/diff")
    assert diff_resp.status_code == 200
    diff_data = diff_resp.json()
    assert diff_data["remediation_id"] == remediation_id
    assert "proposed_code" in diff_data
    assert "unified_diff" in diff_data
    assert "subprocess" in diff_data["proposed_code"]

    # 8. POST /api/v1/remediations/{remediation_id}/validate
    val_resp = client.post(f"/api/v1/remediations/{remediation_id}/validate", json={"strict_mode": True})
    assert val_resp.status_code == 201
    val_data = val_resp.json()
    assert "id" in val_data
    validation_id = val_data["id"]
    assert val_data["is_valid"] is True
    assert val_data["syntax_valid"] is True
    assert val_data["target_vulnerability_eradicated"] is True
    assert val_data["new_findings_count"] == 0

    # 9. GET /api/v1/validations/{validation_id}
    get_val = client.get(f"/api/v1/validations/{validation_id}")
    assert get_val.status_code == 200
    assert get_val.json()["id"] == validation_id
    assert get_val.json()["is_valid"] is True


def test_v1_paginated_scans(client):
    response = client.get("/api/v1/scans?page=1&limit=5")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert data["page"] == 1
    assert "limit" in data
    assert data["limit"] == 5
    assert "pages" in data


def test_v1_error_handling_structure_404(client):
    response = client.get("/api/v1/findings/non_existent_find_999")
    assert response.status_code == 404
    data = response.json()
    assert data["error_code"] == "NOT_FOUND"
    assert "message" in data
    assert "request_id" in data
    assert response.headers.get("X-Request-ID") == data["request_id"]


def test_v1_error_handling_structure_422(client):
    # Missing source_code field
    response = client.post("/api/v1/scans", json={"source_type": "source_code"})
    assert response.status_code == 422
    data = response.json()
    assert data["error_code"] == "VALIDATION_ERROR"
    assert "message" in data
    assert "request_id" in data


def test_v1_disallow_arbitrary_filepath_traversal(client):
    req_payload = {
        "source_type": "source_code",
        "language": "python",
        "filename": "../../etc/shadow",
        "source_code": "x = 1\n"
    }
    response = client.post("/api/v1/scans", json=req_payload)
    assert response.status_code == 201
    data = response.json()
    # Verify traversal was stripped to basename
    assert ".." not in data["target_name"]
    assert "/" not in data["target_name"]
    assert "\\" not in data["target_name"]
    assert data["target_name"] in ("shadow", "shadow.py")


def test_v1_remediation_not_found(client):
    response = client.get("/api/v1/remediations/non_existent_rem_123")
    assert response.status_code == 404
    data = response.json()
    assert data["error_code"] == "NOT_FOUND"


def test_v1_diff_not_found(client):
    response = client.get("/api/v1/remediations/non_existent_rem_123/diff")
    assert response.status_code == 404
    data = response.json()
    assert data["error_code"] == "NOT_FOUND"


def test_v1_validate_not_found(client):
    response = client.post("/api/v1/remediations/non_existent_rem_123/validate")
    assert response.status_code == 404
    data = response.json()
    assert data["error_code"] == "NOT_FOUND"


def test_v1_validation_by_id_not_found(client):
    response = client.get("/api/v1/validations/non_existent_val_123")
    assert response.status_code == 404
    data = response.json()
    assert data["error_code"] == "NOT_FOUND"


def test_v1_repository_scan_ssrf_protection(client):
    payload = {
        "source_type": "repository",
        "repo_url": "https://127.0.0.1/malicious.git"
    }
    response = client.post("/api/v1/scans", json=payload)
    assert response.status_code == 400
    data = response.json()
    assert data["error_code"] == "BAD_REQUEST"
