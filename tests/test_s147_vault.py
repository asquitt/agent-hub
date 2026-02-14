"""S147 — Secret rotation vault tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s147")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s147")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s147")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.secret_vault import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_store_secret() -> None:
    _reset()
    r = client.post(
        "/v1/vault/secrets",
        json={"name": "db-password", "value": "s3cret123", "secret_type": "password"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "db-password"
    assert body["secret_type"] == "password"
    assert body["status"] == "active"
    assert "value_hash" not in body  # value never returned


def test_get_secret() -> None:
    _reset()
    r = client.post(
        "/v1/vault/secrets",
        json={"name": "key1", "value": "val1"},
        headers=HEADERS,
    )
    sid = r.json()["secret_id"]
    r = client.get(f"/v1/vault/secrets/{sid}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["secret_id"] == sid


def test_secret_not_found() -> None:
    _reset()
    r = client.get("/v1/vault/secrets/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_list_secrets() -> None:
    _reset()
    client.post("/v1/vault/secrets", json={"name": "s1", "value": "v1"}, headers=HEADERS)
    client.post("/v1/vault/secrets", json={"name": "s2", "value": "v2"}, headers=HEADERS)
    r = client.get("/v1/vault/secrets", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_access_secret() -> None:
    _reset()
    r = client.post(
        "/v1/vault/secrets",
        json={"name": "s1", "value": "v1", "agent_id": "a1"},
        headers=HEADERS,
    )
    sid = r.json()["secret_id"]

    r = client.post(
        f"/v1/vault/secrets/{sid}/access",
        json={"agent_id": "a1"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["access_count"] == 1


def test_access_unauthorized_agent() -> None:
    _reset()
    r = client.post(
        "/v1/vault/secrets",
        json={"name": "s1", "value": "v1", "agent_id": "a1"},
        headers=HEADERS,
    )
    sid = r.json()["secret_id"]

    r = client.post(
        f"/v1/vault/secrets/{sid}/access",
        json={"agent_id": "a2"},
        headers=HEADERS,
    )
    assert r.status_code == 400
    assert "not authorized" in r.json()["detail"]


def test_rotate_secret() -> None:
    _reset()
    r = client.post(
        "/v1/vault/secrets",
        json={"name": "s1", "value": "v1"},
        headers=HEADERS,
    )
    sid = r.json()["secret_id"]

    r = client.post(
        f"/v1/vault/secrets/{sid}/rotate",
        json={"new_value": "v2"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["version"] == 2


def test_rotation_history() -> None:
    _reset()
    r = client.post(
        "/v1/vault/secrets",
        json={"name": "s1", "value": "v1"},
        headers=HEADERS,
    )
    sid = r.json()["secret_id"]

    client.post(f"/v1/vault/secrets/{sid}/rotate", json={"new_value": "v2"}, headers=HEADERS)
    client.post(f"/v1/vault/secrets/{sid}/rotate", json={"new_value": "v3"}, headers=HEADERS)

    r = client.get(f"/v1/vault/rotation-history?secret_id={sid}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] == 2


def test_revoke_secret() -> None:
    _reset()
    r = client.post(
        "/v1/vault/secrets",
        json={"name": "s1", "value": "v1"},
        headers=HEADERS,
    )
    sid = r.json()["secret_id"]

    r = client.post(f"/v1/vault/secrets/{sid}/revoke", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "expired"


def test_access_revoked_secret() -> None:
    _reset()
    r = client.post(
        "/v1/vault/secrets",
        json={"name": "s1", "value": "v1"},
        headers=HEADERS,
    )
    sid = r.json()["secret_id"]
    client.post(f"/v1/vault/secrets/{sid}/revoke", headers=HEADERS)

    r = client.post(
        f"/v1/vault/secrets/{sid}/access",
        json={"agent_id": "a1"},
        headers=HEADERS,
    )
    assert r.status_code == 400


def test_expiring_secrets() -> None:
    _reset()
    # Short TTL
    client.post(
        "/v1/vault/secrets",
        json={"name": "s1", "value": "v1", "ttl_seconds": 300},
        headers=HEADERS,
    )

    r = client.get("/v1/vault/secrets/expiring?within_seconds=86400", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


def test_list_filter_by_type() -> None:
    _reset()
    client.post(
        "/v1/vault/secrets",
        json={"name": "s1", "value": "v1", "secret_type": "api_key"},
        headers=HEADERS,
    )
    client.post(
        "/v1/vault/secrets",
        json={"name": "s2", "value": "v2", "secret_type": "password"},
        headers=HEADERS,
    )

    r = client.get("/v1/vault/secrets?secret_type=password", headers=HEADERS)
    assert r.status_code == 200
    for s in r.json()["secrets"]:
        assert s["secret_type"] == "password"


if __name__ == "__main__":
    test_store_secret()
    test_get_secret()
    test_secret_not_found()
    test_list_secrets()
    test_access_secret()
    test_access_unauthorized_agent()
    test_rotate_secret()
    test_rotation_history()
    test_revoke_secret()
    test_access_revoked_secret()
    test_expiring_secrets()
    test_list_filter_by_type()
    print("All S147 tests passed!")
