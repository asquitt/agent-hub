from __future__ import annotations

from fastapi.testclient import TestClient

from src.api.app import app


def test_marketing_home_page_serves_public_site() -> None:
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "AgentHub" in response.text
    assert "Build, Trust, and Run Autonomous Agents with Confidence" in response.text
    assert 'href="/operator"' in response.text
    assert 'href="/docs"' in response.text
