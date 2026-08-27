"""S147 — Secret rotation vault tests."""
from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s147")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s147")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s147")
os.environ.setdefault("AGENTHUB_POLICY_SIGNING_SECRET", "test-policy-secret")
os.environ.setdefault("AGENTHUB_VAULT_KEY", "test-vault-key")

from fastapi.testclient import TestClient

from src.api.app import app
from src.identity.storage import register_agent_identity, reset_for_tests as identity_reset
from src.runtime.secret_vault import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    identity_reset()
    for agent_id in ("a1", "a2"):
        register_agent_identity(
            agent_id=agent_id,
            owner="owner-dev",
            credential_type="api_key",
        )
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


def test_rotate_revoked_secret_returns_bad_request() -> None:
    _reset()
    stored = client.post(
        "/v1/vault/secrets",
        json={"name": "revoked", "value": "v1"},
        headers=HEADERS,
    )
    secret_id = stored.json()["secret_id"]
    revoked = client.post(f"/v1/vault/secrets/{secret_id}/revoke", headers=HEADERS)
    rotated = client.post(
        f"/v1/vault/secrets/{secret_id}/rotate",
        json={"new_value": "v2"},
        headers=HEADERS,
    )

    assert revoked.status_code == 200
    assert rotated.status_code == 400
    assert rotated.json()["detail"] == "secret is expired, not active"


@pytest.mark.parametrize("operation", ["rotate", "revoke"])
@pytest.mark.parametrize(
    ("error_type", "expected_status"),
    [(ValueError, 400), (PermissionError, 403)],
)
def test_vault_mutation_routes_map_service_errors(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    error_type: type[Exception],
    expected_status: int,
) -> None:
    def denied(*args: object, **kwargs: object) -> dict[str, object]:
        raise error_type("denied")

    monkeypatch.setattr(f"src.api.routes.vault.{operation}_secret", denied)
    response = client.post(
        f"/v1/vault/secrets/test-secret/{operation}",
        json={"new_value": "v2"} if operation == "rotate" else None,
        headers=HEADERS,
    )

    assert response.status_code == expected_status
    assert response.json()["detail"] == "denied"


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
