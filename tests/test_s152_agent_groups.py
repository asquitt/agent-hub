"""S152 — Agent group policies tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s152")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s152")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s152")
os.environ.setdefault("AGENTHUB_POLICY_SIGNING_SECRET", "test-policy-secret")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.agent_groups import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_create_group() -> None:
    _reset()
    r = client.post(
        "/v1/groups",
        json={"name": "engineering", "policies": {"max_rate": 100}},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "engineering"
    assert body["policies"]["max_rate"] == 100


def test_get_group() -> None:
    _reset()
    r = client.post("/v1/groups", json={"name": "g1"}, headers=HEADERS)
    gid = r.json()["group_id"]
    r = client.get(f"/v1/groups/{gid}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["group_id"] == gid


def test_group_not_found() -> None:
    _reset()
    r = client.get("/v1/groups/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_list_groups() -> None:
    _reset()
    client.post("/v1/groups", json={"name": "g1"}, headers=HEADERS)
    client.post("/v1/groups", json={"name": "g2"}, headers=HEADERS)
    r = client.get("/v1/groups", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_add_remove_member() -> None:
    _reset()
    r = client.post("/v1/groups", json={"name": "g1"}, headers=HEADERS)
    gid = r.json()["group_id"]

    r = client.post(f"/v1/groups/{gid}/members", json={"agent_id": "a1"}, headers=HEADERS)
    assert r.status_code == 200
    assert "a1" in r.json()["members"]

    r = client.post(f"/v1/groups/{gid}/members/remove", json={"agent_id": "a1"}, headers=HEADERS)
    assert r.status_code == 200
    assert "a1" not in r.json()["members"]


def test_get_agent_groups() -> None:
    _reset()
    r = client.post("/v1/groups", json={"name": "g1"}, headers=HEADERS)
    gid = r.json()["group_id"]
    client.post(f"/v1/groups/{gid}/members", json={"agent_id": "a1"}, headers=HEADERS)

    r = client.get("/v1/groups/agents/a1", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


def test_update_policies() -> None:
    _reset()
    r = client.post("/v1/groups", json={"name": "g1", "policies": {"max_rate": 100}}, headers=HEADERS)
    gid = r.json()["group_id"]

    r = client.put(f"/v1/groups/{gid}/policies", json={"policies": {"max_rate": 50}}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["policies"]["max_rate"] == 50


def test_group_hierarchy() -> None:
    _reset()
    r = client.post("/v1/groups", json={"name": "parent", "policies": {"max_rate": 100}}, headers=HEADERS)
    parent_id = r.json()["group_id"]

    r = client.post(
        "/v1/groups",
        json={"name": "child", "parent_group_id": parent_id, "policies": {"max_cost": 500}},
        headers=HEADERS,
    )
    assert r.status_code == 200
    child_id = r.json()["group_id"]

    r = client.get(f"/v1/groups/{parent_id}", headers=HEADERS)
    assert child_id in r.json()["children"]


def test_effective_policy() -> None:
    _reset()
    r = client.post("/v1/groups", json={"name": "g1", "policies": {"max_rate": 100, "max_cost": 1000}}, headers=HEADERS)
    gid1 = r.json()["group_id"]

    r = client.post("/v1/groups", json={"name": "g2", "policies": {"max_rate": 50}}, headers=HEADERS)
    gid2 = r.json()["group_id"]

    client.post(f"/v1/groups/{gid1}/members", json={"agent_id": "a1"}, headers=HEADERS)
    client.post(f"/v1/groups/{gid2}/members", json={"agent_id": "a1"}, headers=HEADERS)

    r = client.get("/v1/groups/agents/a1/effective-policy", headers=HEADERS)
    assert r.status_code == 200
    policies = r.json()["effective_policies"]
    # Most restrictive: min(100, 50) = 50
    assert policies["max_rate"] == 50
    assert policies["max_cost"] == 1000


def test_stats() -> None:
    _reset()
    r = client.post("/v1/groups", json={"name": "g1", "policies": {"x": 1}}, headers=HEADERS)
    gid = r.json()["group_id"]
    client.post(f"/v1/groups/{gid}/members", json={"agent_id": "a1"}, headers=HEADERS)
    client.post("/v1/groups", json={"name": "g2"}, headers=HEADERS)

    r = client.get("/v1/groups/stats", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["total_groups"] == 2
    assert body["total_memberships"] == 1
    assert body["groups_with_policies"] == 1


if __name__ == "__main__":
    test_create_group()
    test_get_group()
    test_group_not_found()
    test_list_groups()
    test_add_remove_member()
    test_get_agent_groups()
    test_update_policies()
    test_group_hierarchy()
    test_effective_policy()
    test_stats()
    print("All S152 tests passed!")
