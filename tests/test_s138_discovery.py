"""S138 — Agent Discovery & Inventory API tests."""
from __future__ import annotations

import json
import os
import tempfile

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s138")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s138")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s138")

from fastapi.testclient import TestClient

from src.api.app import app
from src.identity.storage import reset_for_tests as identity_reset

HEADERS = {"X-API-Key": "test-key"}
_tmpdir = tempfile.mkdtemp()
_db = os.path.join(_tmpdir, "s138.db")


def _reset() -> None:
    os.environ["AGENTHUB_IDENTITY_DB_PATH"] = _db
    identity_reset(db_path=_db)


def _register(agent_id: str) -> None:
    """Register an agent identity (owner comes from API key)."""
    r = client.post(
        "/v1/identity/agents",
        json={"agent_id": agent_id, "credential_type": "api_key"},
        headers=HEADERS,
    )
    assert r.status_code == 200, f"register failed: {r.status_code} {r.text}"


client = TestClient(app)


def test_inventory_empty() -> None:
    _reset()
    r = client.get("/v1/discovery/inventory", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] >= 0
    assert "agents" in body


def test_inventory_with_agent() -> None:
    _reset()
    _register("disc-agent-1")

    r = client.get("/v1/discovery/inventory", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] >= 1
    found = [a for a in body["agents"] if a["agent_id"] == "disc-agent-1"]
    assert len(found) == 1
    assert found[0]["has_identity"] is True


def test_inventory_filter_by_owner() -> None:
    _reset()
    _register("disc-owner-a")
    r = client.get("/v1/discovery/inventory?owner=owner-dev", headers=HEADERS)
    assert r.status_code == 200
    for a in r.json()["agents"]:
        assert a["owner"] == "owner-dev"


def test_inventory_with_credentials() -> None:
    _reset()
    _register("disc-creds")
    client.post(
        "/v1/identity/agents/disc-creds/credentials",
        json={"scopes": ["read"]},
        headers=HEADERS,
    )
    r = client.get(
        "/v1/discovery/inventory?include_credentials=true",
        headers=HEADERS,
    )
    assert r.status_code == 200
    found = [a for a in r.json()["agents"] if a["agent_id"] == "disc-creds"]
    assert len(found) == 1
    assert found[0]["credentials"]["active"] >= 1


def test_agent_profile() -> None:
    _reset()
    _register("disc-prof")
    r = client.get("/v1/discovery/inventory/disc-prof", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["agent_id"] == "disc-prof"
    assert body["identity"] is not None
    assert body["identity"]["owner"] == "owner-dev"
    assert "credentials" in body
    assert "posture" in body


def test_agent_profile_not_found() -> None:
    _reset()
    r = client.get("/v1/discovery/inventory/nonexistent-999", headers=HEADERS)
    assert r.status_code == 404


def test_shadow_agents() -> None:
    _reset()
    r = client.get("/v1/discovery/shadow-agents", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert "shadow_count" in body
    assert "shadow_agents" in body
    assert body["total_identity_agents"] >= 0


def test_posture_summary() -> None:
    _reset()
    _register("posture-agent")
    r = client.get("/v1/discovery/posture", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert "total_agents" in body
    assert "overall_score" in body
    assert 0 <= body["overall_score"] <= 100


def test_posture_with_credentials() -> None:
    _reset()
    _register("posture-cred")
    client.post(
        "/v1/identity/agents/posture-cred/credentials",
        json={"scopes": ["read"]},
        headers=HEADERS,
    )
    r = client.get("/v1/discovery/posture", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["active_credentials"] >= 1


def test_inventory_with_posture() -> None:
    _reset()
    _register("disc-posture")
    r = client.get(
        "/v1/discovery/inventory?include_posture=true",
        headers=HEADERS,
    )
    assert r.status_code == 200
    found = [a for a in r.json()["agents"] if a["agent_id"] == "disc-posture"]
    assert len(found) == 1
    assert "posture" in found[0]
    assert "score" in found[0]["posture"]


if __name__ == "__main__":
    test_inventory_empty()
    test_inventory_with_agent()
    test_inventory_filter_by_owner()
    test_inventory_with_credentials()
    test_agent_profile()
    test_agent_profile_not_found()
    test_shadow_agents()
    test_posture_summary()
    test_posture_with_credentials()
    test_inventory_with_posture()
    print("All S138 tests passed!")
