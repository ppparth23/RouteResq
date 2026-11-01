"""Integration tests for scans endpoints."""

import io


def test_scan_code_endpoint(client):
    payload = {
        "source_code": "import os\ndef test(cmd):\n    os.system(cmd)\n",
        "file_name": "cmd_test.py",
        "language": "python"
    }
    response = client.post("/api/scans/code", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["target_type"] == "code"
    assert data["status"] == "completed"
    assert data["summary"]["total_findings"] >= 1
    assert len(data["findings"]) >= 1
    assert data["findings"][0]["cwe_id"] == "CWE-78"

    # Verify scan can be retrieved by ID
    scan_id = data["id"]
    get_res = client.get(f"/api/scans/{scan_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == scan_id


def test_scan_empty_code_rejected(client):
    payload = {
        "source_code": "",
        "file_name": "empty.py"
    }
    response = client.post("/api/scans/code", json=payload)
    assert response.status_code == 400


def test_scan_file_upload(client):
    file_content = b"import pickle\ndef parse(b):\n    return pickle.loads(b)\n"
    files = {"file": ("vulnerable.py", io.BytesIO(file_content), "text/plain")}
    response = client.post("/api/scans/file", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["target_type"] == "file"
    assert data["summary"]["critical_count"] >= 1
    assert any(f["cwe_id"] == "CWE-502" for f in data["findings"])


def test_list_scans(client):
    response = client.get("/api/scans?limit=10")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
