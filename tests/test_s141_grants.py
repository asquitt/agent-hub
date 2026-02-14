"""S141 — Session-based ephemeral access grant tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s141")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s141")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s141")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.session_grants import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_create_grant() -> None:
    _reset()
    r = client.post(
        "/v1/grants",
        json={"agent_id": "a1", "scopes": ["read"], "ttl_seconds": 60},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["agent_id"] == "a1"
    assert body["status"] == "active"
    assert body["scopes"] == ["read"]
    assert body["grant_type"] == "time_bound"


def test_create_single_use_grant() -> None:
    _reset()
    r = client.post(
        "/v1/grants",
        json={"agent_id": "a1", "scopes": ["write"], "grant_type": "single_use"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["grant_type"] == "single_use"
    assert body["max_uses"] == 1


def test_consume_grant() -> None:
    _reset()
    r = client.post(
        "/v1/grants",
        json={"agent_id": "a1", "scopes": ["read"], "ttl_seconds": 300},
        headers=HEADERS,
    )
    grant_id = r.json()["grant_id"]

    r = client.post(
        f"/v1/grants/{grant_id}/consume",
        json={"action": "read_data"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["consumed"] is True
    assert r.json()["use_count"] == 1


def test_single_use_consumed_after_use() -> None:
    _reset()
    r = client.post(
        "/v1/grants",
        json={"agent_id": "a1", "scopes": ["read"], "grant_type": "single_use"},
        headers=HEADERS,
    )
    grant_id = r.json()["grant_id"]

    # First use
    r = client.post(
        f"/v1/grants/{grant_id}/consume",
        json={"action": "read"},
        headers=HEADERS,
    )
    assert r.json()["consumed"] is True

    # Second use should fail
    r = client.post(
        f"/v1/grants/{grant_id}/consume",
        json={"action": "read_again"},
        headers=HEADERS,
    )
    assert r.json()["consumed"] is False


def test_revoke_grant() -> None:
    _reset()
    r = client.post(
        "/v1/grants",
        json={"agent_id": "a1", "scopes": ["read"]},
        headers=HEADERS,
    )
    grant_id = r.json()["grant_id"]

    r = client.post(f"/v1/grants/{grant_id}/revoke", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "revoked"


def test_consume_revoked_grant() -> None:
    _reset()
    r = client.post(
        "/v1/grants",
        json={"agent_id": "a1", "scopes": ["read"]},
        headers=HEADERS,
    )
    grant_id = r.json()["grant_id"]
    client.post(f"/v1/grants/{grant_id}/revoke", headers=HEADERS)

    r = client.post(
        f"/v1/grants/{grant_id}/consume",
        json={"action": "read"},
        headers=HEADERS,
    )
    assert r.json()["consumed"] is False


def test_check_grant() -> None:
    _reset()
    client.post(
        "/v1/grants",
        json={"agent_id": "a1", "scopes": ["read", "write"]},
        headers=HEADERS,
    )
    r = client.post(
        "/v1/grants/check",
        json={"agent_id": "a1", "scope": "read"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["has_grant"] is True


def test_check_no_grant() -> None:
    _reset()
    r = client.post(
        "/v1/grants/check",
        json={"agent_id": "a1", "scope": "read"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["has_grant"] is False


def test_list_grants() -> None:
    _reset()
    client.post(
        "/v1/grants",
        json={"agent_id": "a1", "scopes": ["read"]},
        headers=HEADERS,
    )
    client.post(
        "/v1/grants",
        json={"agent_id": "a2", "scopes": ["write"]},
        headers=HEADERS,
    )
    r = client.get("/v1/grants", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_list_filter_by_agent() -> None:
    _reset()
    client.post(
        "/v1/grants",
        json={"agent_id": "a1", "scopes": ["read"]},
        headers=HEADERS,
    )
    r = client.get("/v1/grants?agent_id=a1", headers=HEADERS)
    assert r.status_code == 200
    for g in r.json()["grants"]:
        assert g["agent_id"] == "a1"


def test_get_grant_detail() -> None:
    _reset()
    r = client.post(
        "/v1/grants",
        json={"agent_id": "a1", "scopes": ["read"]},
        headers=HEADERS,
    )
    grant_id = r.json()["grant_id"]
    r = client.get(f"/v1/grants/{grant_id}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["grant_id"] == grant_id


def test_grant_not_found() -> None:
    _reset()
    r = client.get("/v1/grants/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_grant_usage_audit() -> None:
    _reset()
    r = client.post(
        "/v1/grants",
        json={"agent_id": "a1", "scopes": ["read"], "max_uses": 3},
        headers=HEADERS,
    )
    grant_id = r.json()["grant_id"]

    client.post(f"/v1/grants/{grant_id}/consume", json={"action": "op1"}, headers=HEADERS)
    client.post(f"/v1/grants/{grant_id}/consume", json={"action": "op2"}, headers=HEADERS)

    r = client.get(f"/v1/grants/usage?grant_id={grant_id}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] == 2


def test_resource_restricted_grant() -> None:
    _reset()
    r = client.post(
        "/v1/grants",
        json={"agent_id": "a1", "scopes": ["read"], "resource": "db/users"},
        headers=HEADERS,
    )
    grant_id = r.json()["grant_id"]

    # Same resource -> ok
    r = client.post(
        f"/v1/grants/{grant_id}/consume",
        json={"resource": "db/users"},
        headers=HEADERS,
    )
    assert r.json()["consumed"] is True

    # Different resource -> rejected
    r = client.post(
        f"/v1/grants/{grant_id}/consume",
        json={"resource": "db/secrets"},
        headers=HEADERS,
    )
    assert r.json()["consumed"] is False


if __name__ == "__main__":
    test_create_grant()
    test_create_single_use_grant()
    test_consume_grant()
    test_single_use_consumed_after_use()
    test_revoke_grant()
    test_consume_revoked_grant()
    test_check_grant()
    test_check_no_grant()
    test_list_grants()
    test_list_filter_by_agent()
    test_get_grant_detail()
    test_grant_not_found()
    test_grant_usage_audit()
    test_resource_restricted_grant()
    print("All S141 tests passed!")
