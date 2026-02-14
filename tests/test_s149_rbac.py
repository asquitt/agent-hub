"""S149 — RBAC tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s149")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s149")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s149")
os.environ.setdefault("AGENTHUB_POLICY_SIGNING_SECRET", "test-policy-secret")
os.environ.setdefault("AGENTHUB_VAULT_KEY", "test-vault-key")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.rbac import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_define_role() -> None:
    _reset()
    r = client.post(
        "/v1/rbac/roles",
        json={"name": "admin", "permissions": ["read:all", "write:all"]},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "admin"
    assert "read:all" in body["permissions"]


def test_get_role() -> None:
    _reset()
    r = client.post("/v1/rbac/roles", json={"name": "viewer", "permissions": ["read:data"]}, headers=HEADERS)
    rid = r.json()["role_id"]
    r = client.get(f"/v1/rbac/roles/{rid}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["name"] == "viewer"
    assert "read:data" in r.json()["effective_permissions"]


def test_list_roles() -> None:
    _reset()
    client.post("/v1/rbac/roles", json={"name": "r1"}, headers=HEADERS)
    client.post("/v1/rbac/roles", json={"name": "r2"}, headers=HEADERS)
    r = client.get("/v1/rbac/roles", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_role_hierarchy() -> None:
    _reset()
    r = client.post("/v1/rbac/roles", json={"name": "base", "permissions": ["read:data"]}, headers=HEADERS)
    parent_id = r.json()["role_id"]

    r = client.post(
        "/v1/rbac/roles",
        json={"name": "admin", "permissions": ["write:data"], "parent_role_id": parent_id},
        headers=HEADERS,
    )
    child_id = r.json()["role_id"]

    r = client.get(f"/v1/rbac/roles/{child_id}", headers=HEADERS)
    effective = r.json()["effective_permissions"]
    assert "read:data" in effective  # inherited
    assert "write:data" in effective  # own


def test_assign_and_check() -> None:
    _reset()
    r = client.post("/v1/rbac/roles", json={"name": "editor", "permissions": ["write:docs"]}, headers=HEADERS)
    rid = r.json()["role_id"]

    r = client.post("/v1/rbac/assignments", json={"role_id": rid, "agent_id": "a1"}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["assigned"] is True

    r = client.post("/v1/rbac/check", json={"agent_id": "a1", "permission": "write:docs"}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["granted"] is True


def test_check_denied() -> None:
    _reset()
    r = client.post("/v1/rbac/check", json={"agent_id": "a1", "permission": "admin:all"}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["granted"] is False


def test_wildcard_permission() -> None:
    _reset()
    r = client.post("/v1/rbac/roles", json={"name": "superadmin", "permissions": ["*"]}, headers=HEADERS)
    rid = r.json()["role_id"]
    client.post("/v1/rbac/assignments", json={"role_id": rid, "agent_id": "a1"}, headers=HEADERS)

    r = client.post("/v1/rbac/check", json={"agent_id": "a1", "permission": "anything"}, headers=HEADERS)
    assert r.json()["granted"] is True


def test_remove_role() -> None:
    _reset()
    r = client.post("/v1/rbac/roles", json={"name": "temp", "permissions": ["read:x"]}, headers=HEADERS)
    rid = r.json()["role_id"]
    client.post("/v1/rbac/assignments", json={"role_id": rid, "agent_id": "a1"}, headers=HEADERS)

    r = client.post("/v1/rbac/assignments/remove", json={"role_id": rid, "agent_id": "a1"}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["removed"] is True

    r = client.post("/v1/rbac/check", json={"agent_id": "a1", "permission": "read:x"}, headers=HEADERS)
    assert r.json()["granted"] is False


def test_agent_roles() -> None:
    _reset()
    r = client.post("/v1/rbac/roles", json={"name": "r1", "permissions": ["p1"]}, headers=HEADERS)
    rid1 = r.json()["role_id"]
    r = client.post("/v1/rbac/roles", json={"name": "r2", "permissions": ["p2"]}, headers=HEADERS)
    rid2 = r.json()["role_id"]
    client.post("/v1/rbac/assignments", json={"role_id": rid1, "agent_id": "a1"}, headers=HEADERS)
    client.post("/v1/rbac/assignments", json={"role_id": rid2, "agent_id": "a1"}, headers=HEADERS)

    r = client.get("/v1/rbac/agents/a1/roles", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] == 2


def test_sod_constraint() -> None:
    _reset()
    r1 = client.post("/v1/rbac/roles", json={"name": "approver", "permissions": ["approve"]}, headers=HEADERS)
    r2 = client.post("/v1/rbac/roles", json={"name": "requester", "permissions": ["request"]}, headers=HEADERS)
    rid1 = r1.json()["role_id"]
    rid2 = r2.json()["role_id"]

    r = client.post(
        "/v1/rbac/sod-constraints",
        json={"name": "approve-request", "role_ids": [rid1, rid2]},
        headers=HEADERS,
    )
    assert r.status_code == 200

    # Assign first role
    client.post("/v1/rbac/assignments", json={"role_id": rid1, "agent_id": "a1"}, headers=HEADERS)

    # Try to assign conflicting role — should fail
    r = client.post("/v1/rbac/assignments", json={"role_id": rid2, "agent_id": "a1"}, headers=HEADERS)
    assert r.status_code == 400
    assert "SoD violation" in r.json()["detail"]


def test_list_sod_constraints() -> None:
    _reset()
    r1 = client.post("/v1/rbac/roles", json={"name": "r1"}, headers=HEADERS)
    r2 = client.post("/v1/rbac/roles", json={"name": "r2"}, headers=HEADERS)
    client.post(
        "/v1/rbac/sod-constraints",
        json={"name": "c1", "role_ids": [r1.json()["role_id"], r2.json()["role_id"]]},
        headers=HEADERS,
    )
    r = client.get("/v1/rbac/sod-constraints", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


def test_check_log() -> None:
    _reset()
    client.post("/v1/rbac/check", json={"agent_id": "a1", "permission": "read"}, headers=HEADERS)
    client.post("/v1/rbac/check", json={"agent_id": "a2", "permission": "write"}, headers=HEADERS)
    r = client.get("/v1/rbac/check-log", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_stats() -> None:
    _reset()
    r1 = client.post("/v1/rbac/roles", json={"name": "r1", "permissions": ["p1"]}, headers=HEADERS)
    client.post("/v1/rbac/assignments", json={"role_id": r1.json()["role_id"], "agent_id": "a1"}, headers=HEADERS)
    client.post("/v1/rbac/check", json={"agent_id": "a1", "permission": "p1"}, headers=HEADERS)

    r = client.get("/v1/rbac/stats", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["total_roles"] >= 1
    assert body["total_assignments"] >= 1
    assert body["total_checks"] >= 1


if __name__ == "__main__":
    test_define_role()
    test_get_role()
    test_list_roles()
    test_role_hierarchy()
    test_assign_and_check()
    test_check_denied()
    test_wildcard_permission()
    test_remove_role()
    test_agent_roles()
    test_sod_constraint()
    test_list_sod_constraints()
    test_check_log()
    test_stats()
    print("All S149 tests passed!")
