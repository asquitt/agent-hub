"""S148 — Entitlement catalog tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s148")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s148")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s148")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.entitlements import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_create_entitlement() -> None:
    _reset()
    r = client.post(
        "/v1/entitlements",
        json={"name": "read:data", "entitlement_type": "permission", "risk_level": "low"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "read:data"
    assert body["entitlement_type"] == "permission"
    assert body["risk_level"] == "low"


def test_get_entitlement() -> None:
    _reset()
    r = client.post("/v1/entitlements", json={"name": "e1"}, headers=HEADERS)
    eid = r.json()["entitlement_id"]
    r = client.get(f"/v1/entitlements/{eid}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["entitlement_id"] == eid


def test_entitlement_not_found() -> None:
    _reset()
    r = client.get("/v1/entitlements/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_list_entitlements() -> None:
    _reset()
    client.post("/v1/entitlements", json={"name": "e1"}, headers=HEADERS)
    client.post("/v1/entitlements", json={"name": "e2"}, headers=HEADERS)
    r = client.get("/v1/entitlements", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_list_filter_by_type() -> None:
    _reset()
    client.post("/v1/entitlements", json={"name": "e1", "entitlement_type": "permission"}, headers=HEADERS)
    client.post("/v1/entitlements", json={"name": "e2", "entitlement_type": "api_scope"}, headers=HEADERS)
    r = client.get("/v1/entitlements?entitlement_type=api_scope", headers=HEADERS)
    assert r.status_code == 200
    for e in r.json()["entitlements"]:
        assert e["entitlement_type"] == "api_scope"


def test_assign_entitlement() -> None:
    _reset()
    r = client.post("/v1/entitlements", json={"name": "e1"}, headers=HEADERS)
    eid = r.json()["entitlement_id"]

    r = client.post(
        "/v1/entitlements/assignments",
        json={"agent_id": "a1", "entitlement_id": eid, "reason": "needed"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["agent_id"] == "a1"
    assert r.json()["status"] == "active"


def test_duplicate_assignment_rejected() -> None:
    _reset()
    r = client.post("/v1/entitlements", json={"name": "e1"}, headers=HEADERS)
    eid = r.json()["entitlement_id"]

    client.post("/v1/entitlements/assignments", json={"agent_id": "a1", "entitlement_id": eid}, headers=HEADERS)
    r = client.post("/v1/entitlements/assignments", json={"agent_id": "a1", "entitlement_id": eid}, headers=HEADERS)
    assert r.status_code == 400


def test_revoke_assignment() -> None:
    _reset()
    r = client.post("/v1/entitlements", json={"name": "e1"}, headers=HEADERS)
    eid = r.json()["entitlement_id"]

    r = client.post("/v1/entitlements/assignments", json={"agent_id": "a1", "entitlement_id": eid}, headers=HEADERS)
    aid = r.json()["assignment_id"]

    r = client.post(f"/v1/entitlements/assignments/{aid}/revoke", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "revoked"


def test_get_agent_entitlements() -> None:
    _reset()
    r = client.post("/v1/entitlements", json={"name": "e1"}, headers=HEADERS)
    eid = r.json()["entitlement_id"]
    client.post("/v1/entitlements/assignments", json={"agent_id": "a1", "entitlement_id": eid}, headers=HEADERS)

    r = client.get("/v1/entitlements/agents/a1", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


def test_create_role() -> None:
    _reset()
    r = client.post("/v1/entitlements", json={"name": "e1"}, headers=HEADERS)
    eid = r.json()["entitlement_id"]

    r = client.post(
        "/v1/entitlements/roles",
        json={"name": "admin", "entitlement_ids": [eid], "members": ["a1"]},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["name"] == "admin"
    assert eid in r.json()["entitlement_ids"]


def test_list_roles() -> None:
    _reset()
    client.post("/v1/entitlements/roles", json={"name": "r1"}, headers=HEADERS)
    client.post("/v1/entitlements/roles", json={"name": "r2"}, headers=HEADERS)
    r = client.get("/v1/entitlements/roles", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_role_members() -> None:
    _reset()
    r = client.post("/v1/entitlements/roles", json={"name": "r1"}, headers=HEADERS)
    rid = r.json()["role_id"]

    r = client.post(f"/v1/entitlements/roles/{rid}/members", json={"agent_id": "a1"}, headers=HEADERS)
    assert r.status_code == 200
    assert "a1" in r.json()["members"]

    r = client.post(f"/v1/entitlements/roles/{rid}/members/remove", json={"agent_id": "a1"}, headers=HEADERS)
    assert r.status_code == 200
    assert "a1" not in r.json()["members"]


def test_role_entitlements_appear_for_agent() -> None:
    _reset()
    r = client.post("/v1/entitlements", json={"name": "e1"}, headers=HEADERS)
    eid = r.json()["entitlement_id"]

    r = client.post(
        "/v1/entitlements/roles",
        json={"name": "dev", "entitlement_ids": [eid], "members": ["a1"]},
        headers=HEADERS,
    )

    r = client.get("/v1/entitlements/agents/a1", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 1
    sources = [e.get("source") for e in r.json()["entitlements"]]
    assert "role" in sources


def test_catalog_stats() -> None:
    _reset()
    client.post("/v1/entitlements", json={"name": "e1", "risk_level": "high"}, headers=HEADERS)
    client.post("/v1/entitlements", json={"name": "e2", "risk_level": "low"}, headers=HEADERS)
    r = client.get("/v1/entitlements/stats", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["total_entitlements"] == 2
    assert body["high_risk_entitlements"] == 1


if __name__ == "__main__":
    test_create_entitlement()
    test_get_entitlement()
    test_entitlement_not_found()
    test_list_entitlements()
    test_list_filter_by_type()
    test_assign_entitlement()
    test_duplicate_assignment_rejected()
    test_revoke_assignment()
    test_get_agent_entitlements()
    test_create_role()
    test_list_roles()
    test_role_members()
    test_role_entitlements_appear_for_agent()
    test_catalog_stats()
    print("All S148 tests passed!")
