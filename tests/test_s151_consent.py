"""S151 — Consent and authorization registry tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s151")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s151")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s151")
os.environ.setdefault("AGENTHUB_POLICY_SIGNING_SECRET", "test-policy-secret")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.consent_registry import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_grant_consent() -> None:
    _reset()
    r = client.post(
        "/v1/consents",
        json={"principal_id": "user1", "agent_id": "a1", "scopes": ["read:data"], "purpose": "analytics"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["principal_id"] == "user1"
    assert body["agent_id"] == "a1"
    assert body["status"] == "active"
    assert "read:data" in body["scopes"]


def test_get_consent() -> None:
    _reset()
    r = client.post(
        "/v1/consents",
        json={"principal_id": "u1", "agent_id": "a1", "scopes": ["s1"]},
        headers=HEADERS,
    )
    cid = r.json()["consent_id"]
    r = client.get(f"/v1/consents/{cid}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["consent_id"] == cid


def test_consent_not_found() -> None:
    _reset()
    r = client.get("/v1/consents/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_list_consents() -> None:
    _reset()
    client.post("/v1/consents", json={"principal_id": "u1", "agent_id": "a1", "scopes": ["s1"]}, headers=HEADERS)
    client.post("/v1/consents", json={"principal_id": "u2", "agent_id": "a2", "scopes": ["s2"]}, headers=HEADERS)
    r = client.get("/v1/consents", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_list_filter_by_agent() -> None:
    _reset()
    client.post("/v1/consents", json={"principal_id": "u1", "agent_id": "a1", "scopes": ["s1"]}, headers=HEADERS)
    client.post("/v1/consents", json={"principal_id": "u2", "agent_id": "a2", "scopes": ["s2"]}, headers=HEADERS)
    r = client.get("/v1/consents?agent_id=a1", headers=HEADERS)
    assert r.status_code == 200
    for c in r.json()["consents"]:
        assert c["agent_id"] == "a1"


def test_revoke_consent() -> None:
    _reset()
    r = client.post(
        "/v1/consents",
        json={"principal_id": "u1", "agent_id": "a1", "scopes": ["s1"]},
        headers=HEADERS,
    )
    cid = r.json()["consent_id"]

    r = client.post(f"/v1/consents/{cid}/revoke", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "revoked"


def test_check_consent_authorized() -> None:
    _reset()
    client.post(
        "/v1/consents",
        json={"principal_id": "u1", "agent_id": "a1", "scopes": ["read:data", "write:data"]},
        headers=HEADERS,
    )

    r = client.post(
        "/v1/consents/check",
        json={"principal_id": "u1", "agent_id": "a1", "scope": "read:data"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["authorized"] is True


def test_check_consent_denied() -> None:
    _reset()
    r = client.post(
        "/v1/consents/check",
        json={"principal_id": "u1", "agent_id": "a1", "scope": "admin:all"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["authorized"] is False


def test_check_consent_revoked() -> None:
    _reset()
    r = client.post(
        "/v1/consents",
        json={"principal_id": "u1", "agent_id": "a1", "scopes": ["s1"]},
        headers=HEADERS,
    )
    cid = r.json()["consent_id"]
    client.post(f"/v1/consents/{cid}/revoke", headers=HEADERS)

    r = client.post(
        "/v1/consents/check",
        json={"principal_id": "u1", "agent_id": "a1", "scope": "s1"},
        headers=HEADERS,
    )
    assert r.json()["authorized"] is False


def test_wildcard_consent() -> None:
    _reset()
    client.post(
        "/v1/consents",
        json={"principal_id": "u1", "agent_id": "a1", "scopes": ["*"]},
        headers=HEADERS,
    )

    r = client.post(
        "/v1/consents/check",
        json={"principal_id": "u1", "agent_id": "a1", "scope": "anything"},
        headers=HEADERS,
    )
    assert r.json()["authorized"] is True


def test_audit_trail() -> None:
    _reset()
    r = client.post(
        "/v1/consents",
        json={"principal_id": "u1", "agent_id": "a1", "scopes": ["s1"]},
        headers=HEADERS,
    )
    cid = r.json()["consent_id"]
    client.post(f"/v1/consents/{cid}/revoke", headers=HEADERS)

    r = client.get("/v1/consents/audit-trail", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2  # grant + revoke


def test_stats() -> None:
    _reset()
    client.post("/v1/consents", json={"principal_id": "u1", "agent_id": "a1", "scopes": ["s1"]}, headers=HEADERS)
    r = client.post("/v1/consents", json={"principal_id": "u2", "agent_id": "a2", "scopes": ["s2"]}, headers=HEADERS)
    cid = r.json()["consent_id"]
    client.post(f"/v1/consents/{cid}/revoke", headers=HEADERS)

    r = client.get("/v1/consents/stats", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["total_consents"] == 2
    assert body["active_consents"] == 1
    assert body["revoked_consents"] == 1


if __name__ == "__main__":
    test_grant_consent()
    test_get_consent()
    test_consent_not_found()
    test_list_consents()
    test_list_filter_by_agent()
    test_revoke_consent()
    test_check_consent_authorized()
    test_check_consent_denied()
    test_check_consent_revoked()
    test_wildcard_consent()
    test_audit_trail()
    test_stats()
    print("All S151 tests passed!")
