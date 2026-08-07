"""FastAPI Endpoints Integration Test Suite."""

import pytest


def test_health_check(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


def test_platform_statistics(client):
    resp = client.get("/api/v1/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_analyzed" in data
    assert "malicious_indicators" in data
    assert "type_distribution" in data


def test_analyze_ip_endpoint(client):
    payload = {"indicator": "194.26.29.112", "use_cache": False}
    resp = client.post("/api/v1/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["indicator_type"] == "IP"
    assert data["normalized"] == "194.26.29.112"
    assert data["risk_assessment"]["risk_score"] >= 70.0


def test_extract_iocs_endpoint(client):
    raw_text = "Adversary contacted hxxp://evil-site[.]org/payload[.]exe and IP 185.220.101.5."
    resp = client.post("/api/v1/extract", json={"text": raw_text})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_found"] >= 2
    assert len(data["ips"]) >= 1
    assert len(data["urls"]) >= 1


def test_defang_endpoint(client):
    resp = client.post("/api/v1/extract/defang", json={"ioc": "http://malicious.com", "defang": True})
    assert resp.status_code == 200
    assert resp.json()["result"] == "hxxp://malicious[.]com"


def test_batch_analyze_endpoint(client):
    payload = {
        "indicators": ["194.26.29.112", "malicious-payload-cdn.net"],
        "use_cache": True
    }
    resp = client.post("/api/v1/batch", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_submitted"] == 2
    assert len(data["results"]) == 2


def test_history_endpoint(client):
    # Ensure an IOC is analyzed first
    client.post("/api/v1/analyze", json={"indicator": "194.26.29.112"})
    
    resp = client.get("/api/v1/history")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert len(data["items"]) >= 1


def test_provider_status_endpoint(client):
    resp = client.get("/api/v1/config/providers")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 4
    # Ensure API keys are NOT exposed
    for p in data:
        assert "api_key" not in p


def test_scoring_weights_endpoint(client):
    resp = client.get("/api/v1/config/weights")
    assert resp.status_code == 200
    data = resp.json()
    assert "normalized_weights" in data
    assert "methodology" in data
