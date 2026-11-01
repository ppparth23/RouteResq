"""Tests for health and discovery endpoints."""

def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "Vulnex AI Backend"
    assert "/docs" in data["documentation"]


def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("healthy", "degraded")
    assert "timestamp" in data
    assert "database" in data
