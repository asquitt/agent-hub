"""S150 — Agent key management tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s150")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s150")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s150")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.key_management import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_create_key() -> None:
    _reset()
    r = client.post(
        "/v1/keys",
        json={"agent_id": "a1", "name": "my-key", "scopes": ["read:data"]},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["agent_id"] == "a1"
    assert body["name"] == "my-key"
    assert body["raw_key"].startswith("ahk_")
    assert body["status"] == "active"


def test_get_key() -> None:
    _reset()
    r = client.post("/v1/keys", json={"agent_id": "a1"}, headers=HEADERS)
    kid = r.json()["key_id"]
    r = client.get(f"/v1/keys/{kid}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["key_id"] == kid
    assert "raw_key" not in r.json()  # not exposed on get


def test_key_not_found() -> None:
    _reset()
    r = client.get("/v1/keys/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_list_keys() -> None:
    _reset()
    client.post("/v1/keys", json={"agent_id": "a1"}, headers=HEADERS)
    client.post("/v1/keys", json={"agent_id": "a2"}, headers=HEADERS)
    r = client.get("/v1/keys", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_list_keys_filter_agent() -> None:
    _reset()
    client.post("/v1/keys", json={"agent_id": "a1"}, headers=HEADERS)
    client.post("/v1/keys", json={"agent_id": "a2"}, headers=HEADERS)
    r = client.get("/v1/keys?agent_id=a1", headers=HEADERS)
    assert r.status_code == 200
    for k in r.json()["keys"]:
        assert k["agent_id"] == "a1"


def test_rotate_key() -> None:
    _reset()
    r = client.post("/v1/keys", json={"agent_id": "a1"}, headers=HEADERS)
    kid = r.json()["key_id"]

    r = client.post(f"/v1/keys/{kid}/rotate", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["old_key_id"] == kid
    assert body["new_key_id"] != kid
    assert body["raw_key"].startswith("ahk_")

    # Old key should be rotated
    r = client.get(f"/v1/keys/{kid}", headers=HEADERS)
    assert r.json()["status"] == "rotated"


def test_revoke_key() -> None:
    _reset()
    r = client.post("/v1/keys", json={"agent_id": "a1"}, headers=HEADERS)
    kid = r.json()["key_id"]

    r = client.post(f"/v1/keys/{kid}/revoke", json={"reason": "compromised"}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "revoked"


def test_record_usage() -> None:
    _reset()
    r = client.post("/v1/keys", json={"agent_id": "a1"}, headers=HEADERS)
    kid = r.json()["key_id"]

    r = client.post("/v1/keys/record-usage", json={"key_id": kid}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["use_count"] == 1

    r = client.post("/v1/keys/record-usage", json={"key_id": kid}, headers=HEADERS)
    assert r.json()["use_count"] == 2


def test_usage_revoked_key() -> None:
    _reset()
    r = client.post("/v1/keys", json={"agent_id": "a1"}, headers=HEADERS)
    kid = r.json()["key_id"]
    client.post(f"/v1/keys/{kid}/revoke", headers=HEADERS)

    r = client.post("/v1/keys/record-usage", json={"key_id": kid}, headers=HEADERS)
    assert r.status_code == 400


def test_usage_log() -> None:
    _reset()
    r = client.post("/v1/keys", json={"agent_id": "a1"}, headers=HEADERS)
    kid = r.json()["key_id"]
    client.post("/v1/keys/record-usage", json={"key_id": kid}, headers=HEADERS)

    r = client.get(f"/v1/keys/usage?key_id={kid}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


def test_stats() -> None:
    _reset()
    client.post("/v1/keys", json={"agent_id": "a1"}, headers=HEADERS)
    r = client.post("/v1/keys", json={"agent_id": "a2"}, headers=HEADERS)
    kid = r.json()["key_id"]
    client.post(f"/v1/keys/{kid}/revoke", headers=HEADERS)

    r = client.get("/v1/keys/stats", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["total_keys"] == 2
    assert body["active_keys"] == 1
    assert body["revoked_keys"] == 1


if __name__ == "__main__":
    test_create_key()
    test_get_key()
    test_key_not_found()
    test_list_keys()
    test_list_keys_filter_agent()
    test_rotate_key()
    test_revoke_key()
    test_record_usage()
    test_usage_revoked_key()
    test_usage_log()
    test_stats()
    print("All S150 tests passed!")
