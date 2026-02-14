"""S156 — Environment-based access controls tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s156")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s156")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s156")
os.environ.setdefault("AGENTHUB_POLICY_SIGNING_SECRET", "test-policy-secret")
os.environ.setdefault("AGENTHUB_VAULT_KEY", "test-vault-key")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.env_access import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_create_environment() -> None:
    _reset()
    r = client.post(
        "/v1/environments",
        json={"name": "dev", "tier": "development"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "dev"
    assert body["tier"] == "development"


def test_invalid_tier() -> None:
    _reset()
    r = client.post(
        "/v1/environments",
        json={"name": "x", "tier": "invalid"},
        headers=HEADERS,
    )
    assert r.status_code == 400


def test_get_environment() -> None:
    _reset()
    r = client.post(
        "/v1/environments",
        json={"name": "staging", "tier": "staging"},
        headers=HEADERS,
    )
    eid = r.json()["env_id"]
    r = client.get(f"/v1/environments/{eid}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["env_id"] == eid


def test_env_not_found() -> None:
    _reset()
    r = client.get("/v1/environments/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_list_environments() -> None:
    _reset()
    client.post("/v1/environments", json={"name": "dev", "tier": "development"}, headers=HEADERS)
    client.post("/v1/environments", json={"name": "prod", "tier": "production"}, headers=HEADERS)
    r = client.get("/v1/environments", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_register_and_check_access() -> None:
    _reset()
    r = client.post(
        "/v1/environments",
        json={"name": "dev", "tier": "development", "allowed_actions": ["read", "write"]},
        headers=HEADERS,
    )
    eid = r.json()["env_id"]

    # Register agent
    r = client.post(f"/v1/environments/{eid}/register", json={"agent_id": "a1"}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["registered"] is True

    # Check allowed action
    r = client.post(
        "/v1/environments/check",
        json={"agent_id": "a1", "env_id": eid, "action": "read"},
        headers=HEADERS,
    )
    assert r.json()["allowed"] is True

    # Check blocked action
    r = client.post(
        "/v1/environments/check",
        json={"agent_id": "a1", "env_id": eid, "action": "delete"},
        headers=HEADERS,
    )
    assert r.json()["allowed"] is False
    assert r.json()["reason"] == "action_not_allowed"


def test_unregistered_agent_denied() -> None:
    _reset()
    r = client.post(
        "/v1/environments",
        json={"name": "dev", "tier": "development"},
        headers=HEADERS,
    )
    eid = r.json()["env_id"]

    r = client.post(
        "/v1/environments/check",
        json={"agent_id": "a1", "env_id": eid, "action": "read"},
        headers=HEADERS,
    )
    assert r.json()["allowed"] is False
    assert r.json()["reason"] == "agent_not_registered"


def test_promote_agent() -> None:
    _reset()
    r1 = client.post("/v1/environments", json={"name": "dev", "tier": "development"}, headers=HEADERS)
    r2 = client.post("/v1/environments", json={"name": "staging", "tier": "staging"}, headers=HEADERS)
    dev_id = r1.json()["env_id"]
    staging_id = r2.json()["env_id"]

    # Register in dev
    client.post(f"/v1/environments/{dev_id}/register", json={"agent_id": "a1"}, headers=HEADERS)

    # Promote to staging
    r = client.post(
        "/v1/environments/promote",
        json={"agent_id": "a1", "from_env_id": dev_id, "to_env_id": staging_id},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["from_tier"] == "development"
    assert r.json()["to_tier"] == "staging"


def test_promote_wrong_direction() -> None:
    _reset()
    r1 = client.post("/v1/environments", json={"name": "prod", "tier": "production"}, headers=HEADERS)
    r2 = client.post("/v1/environments", json={"name": "dev", "tier": "development"}, headers=HEADERS)
    prod_id = r1.json()["env_id"]
    dev_id = r2.json()["env_id"]

    client.post(f"/v1/environments/{prod_id}/register", json={"agent_id": "a1"}, headers=HEADERS)

    r = client.post(
        "/v1/environments/promote",
        json={"agent_id": "a1", "from_env_id": prod_id, "to_env_id": dev_id},
        headers=HEADERS,
    )
    assert r.status_code == 400


def test_policy_blocks_action() -> None:
    _reset()
    r = client.post(
        "/v1/environments",
        json={"name": "prod", "tier": "production"},
        headers=HEADERS,
    )
    eid = r.json()["env_id"]

    # Create blocking policy
    client.post(
        "/v1/environments/policies",
        json={"env_id": eid, "name": "no-delete", "rules": {"blocked_actions": ["delete"]}},
        headers=HEADERS,
    )

    # Register agent
    client.post(f"/v1/environments/{eid}/register", json={"agent_id": "a1"}, headers=HEADERS)

    # Check blocked action
    r = client.post(
        "/v1/environments/check",
        json={"agent_id": "a1", "env_id": eid, "action": "delete"},
        headers=HEADERS,
    )
    assert r.json()["allowed"] is False
    assert r.json()["reason"] == "policy_violation"


def test_unregister_agent() -> None:
    _reset()
    r = client.post("/v1/environments", json={"name": "dev", "tier": "development"}, headers=HEADERS)
    eid = r.json()["env_id"]

    client.post(f"/v1/environments/{eid}/register", json={"agent_id": "a1"}, headers=HEADERS)
    r = client.post(f"/v1/environments/{eid}/unregister", json={"agent_id": "a1"}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["unregistered"] is True


def test_promotion_log() -> None:
    _reset()
    r1 = client.post("/v1/environments", json={"name": "dev", "tier": "development"}, headers=HEADERS)
    r2 = client.post("/v1/environments", json={"name": "staging", "tier": "staging"}, headers=HEADERS)
    dev_id = r1.json()["env_id"]
    staging_id = r2.json()["env_id"]

    client.post(f"/v1/environments/{dev_id}/register", json={"agent_id": "a1"}, headers=HEADERS)
    client.post(
        "/v1/environments/promote",
        json={"agent_id": "a1", "from_env_id": dev_id, "to_env_id": staging_id},
        headers=HEADERS,
    )

    r = client.get("/v1/environments/promotions", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


def test_stats() -> None:
    _reset()
    client.post("/v1/environments", json={"name": "dev", "tier": "development"}, headers=HEADERS)
    r = client.get("/v1/environments/stats", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total_environments"] >= 1


if __name__ == "__main__":
    test_create_environment()
    test_invalid_tier()
    test_get_environment()
    test_env_not_found()
    test_list_environments()
    test_register_and_check_access()
    test_unregistered_agent_denied()
    test_promote_agent()
    test_promote_wrong_direction()
    test_policy_blocks_action()
    test_unregister_agent()
    test_promotion_log()
    test_stats()
    print("All S156 tests passed!")
