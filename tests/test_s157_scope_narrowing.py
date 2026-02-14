"""S157 — Token scope narrowing tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s157")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s157")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s157")
os.environ.setdefault("AGENTHUB_POLICY_SIGNING_SECRET", "test-policy-secret")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.scope_narrowing import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_narrow_scope() -> None:
    _reset()
    r = client.post(
        "/v1/scope-narrowing",
        json={
            "parent_token_id": "pt-1",
            "parent_scopes": ["read:data", "write:data", "admin:all"],
            "requested_scopes": ["read:data"],
            "agent_id": "a1",
        },
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["narrowed_scopes"] == ["read:data"]
    assert "write:data" in body["scopes_removed"]
    assert body["active"] is True


def test_scope_escalation_denied() -> None:
    _reset()
    r = client.post(
        "/v1/scope-narrowing",
        json={
            "parent_token_id": "pt-1",
            "parent_scopes": ["read:data"],
            "requested_scopes": ["read:data", "write:data"],
            "agent_id": "a1",
        },
        headers=HEADERS,
    )
    assert r.status_code == 400
    assert "escalation" in r.json()["detail"]


def test_empty_scopes_rejected() -> None:
    _reset()
    r = client.post(
        "/v1/scope-narrowing",
        json={
            "parent_token_id": "pt-1",
            "parent_scopes": ["read:data"],
            "requested_scopes": [],
            "agent_id": "a1",
        },
        headers=HEADERS,
    )
    assert r.status_code == 400


def test_get_narrowed_token() -> None:
    _reset()
    r = client.post(
        "/v1/scope-narrowing",
        json={
            "parent_token_id": "pt-1",
            "parent_scopes": ["read:data", "write:data"],
            "requested_scopes": ["read:data"],
            "agent_id": "a1",
        },
        headers=HEADERS,
    )
    tid = r.json()["token_id"]
    r = client.get(f"/v1/scope-narrowing/{tid}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["token_id"] == tid


def test_token_not_found() -> None:
    _reset()
    r = client.get("/v1/scope-narrowing/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_list_narrowed_tokens() -> None:
    _reset()
    client.post(
        "/v1/scope-narrowing",
        json={"parent_token_id": "pt-1", "parent_scopes": ["a", "b"], "requested_scopes": ["a"], "agent_id": "a1"},
        headers=HEADERS,
    )
    client.post(
        "/v1/scope-narrowing",
        json={"parent_token_id": "pt-2", "parent_scopes": ["x", "y"], "requested_scopes": ["x"], "agent_id": "a2"},
        headers=HEADERS,
    )
    r = client.get("/v1/scope-narrowing", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_validate_active_token() -> None:
    _reset()
    r = client.post(
        "/v1/scope-narrowing",
        json={"parent_token_id": "pt-1", "parent_scopes": ["a"], "requested_scopes": ["a"], "agent_id": "a1"},
        headers=HEADERS,
    )
    tid = r.json()["token_id"]
    r = client.post("/v1/scope-narrowing/validate", json={"token_id": tid}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["valid"] is True


def test_validate_nonexistent() -> None:
    _reset()
    r = client.post("/v1/scope-narrowing/validate", json={"token_id": "nope"}, headers=HEADERS)
    assert r.json()["valid"] is False
    assert r.json()["reason"] == "not_found"


def test_revoke_token() -> None:
    _reset()
    r = client.post(
        "/v1/scope-narrowing",
        json={"parent_token_id": "pt-1", "parent_scopes": ["a"], "requested_scopes": ["a"], "agent_id": "a1"},
        headers=HEADERS,
    )
    tid = r.json()["token_id"]
    r = client.post(f"/v1/scope-narrowing/{tid}/revoke", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["active"] is False

    # Validate should show revoked
    r = client.post("/v1/scope-narrowing/validate", json={"token_id": tid}, headers=HEADERS)
    assert r.json()["valid"] is False
    assert r.json()["reason"] == "revoked"


def test_narrowing_log() -> None:
    _reset()
    client.post(
        "/v1/scope-narrowing",
        json={"parent_token_id": "pt-1", "parent_scopes": ["a", "b"], "requested_scopes": ["a"], "agent_id": "a1"},
        headers=HEADERS,
    )
    r = client.get("/v1/scope-narrowing/log", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


def test_wildcard_parent() -> None:
    _reset()
    r = client.post(
        "/v1/scope-narrowing",
        json={"parent_token_id": "pt-1", "parent_scopes": ["*"], "requested_scopes": ["anything"], "agent_id": "a1"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["narrowed_scopes"] == ["anything"]


def test_stats() -> None:
    _reset()
    client.post(
        "/v1/scope-narrowing",
        json={"parent_token_id": "pt-1", "parent_scopes": ["a"], "requested_scopes": ["a"], "agent_id": "a1"},
        headers=HEADERS,
    )
    r = client.get("/v1/scope-narrowing/stats", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total_narrowed_tokens"] >= 1


if __name__ == "__main__":
    test_narrow_scope()
    test_scope_escalation_denied()
    test_empty_scopes_rejected()
    test_get_narrowed_token()
    test_token_not_found()
    test_list_narrowed_tokens()
    test_validate_active_token()
    test_validate_nonexistent()
    test_revoke_token()
    test_narrowing_log()
    test_wildcard_parent()
    test_stats()
    print("All S157 tests passed!")
