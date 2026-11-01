"""Tests for remediation and patch generation."""

def test_explain_vulnerability_endpoint(client):
    payload = {
        "rule_id": "VULN-SQLI-001",
        "cwe_id": "CWE-89",
        "code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
    }
    response = client.post("/api/remediation/explain", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "explanation" in data
    assert "risk_analysis" in data
    assert len(data["safe_coding_guidelines"]) > 0
    assert len(data["references"]) > 0


def test_generate_patch_and_validate(client):
    vulnerable_code = """import os
def run_backup(path):
    os.system("tar -czf backup.tar.gz " + path)
"""
    payload = {
        "source_code": vulnerable_code,
        "rule_id": "VULN-CMDI-001",
        "cwe_id": "CWE-78",
        "file_name": "backup.py"
    }
    response = client.post("/api/remediation/generate-patch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "remediation_id" in data
    assert "patched_code" in data
    assert "unified_diff" in data
    assert data["validation_status"] == "VALIDATED"
    assert data["validation_details"]["is_valid"] is True
    assert data["validation_details"]["target_vulnerability_eradicated"] is True

    # Retrieve remediation record
    rem_id = data["remediation_id"]
    get_res = client.get(f"/api/remediation/{rem_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == rem_id
