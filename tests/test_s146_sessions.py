"""S146 — Agent session management tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s146")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s146")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s146")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.sessions import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_create_session() -> None:
    _reset()
    r = client.post(
        "/v1/sessions",
        json={"agent_id": "a1", "ttl_seconds": 3600},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["agent_id"] == "a1"
    assert body["status"] == "active"


def test_list_sessions() -> None:
    _reset()
    client.post("/v1/sessions", json={"agent_id": "a1"}, headers=HEADERS)
    client.post("/v1/sessions", json={"agent_id": "a2"}, headers=HEADERS)
    r = client.get("/v1/sessions", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_get_session() -> None:
    _reset()
    r = client.post("/v1/sessions", json={"agent_id": "a1"}, headers=HEADERS)
    sid = r.json()["session_id"]
    r = client.get(f"/v1/sessions/{sid}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["session_id"] == sid


def test_session_not_found() -> None:
    _reset()
    r = client.get("/v1/sessions/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_touch_session() -> None:
    _reset()
    r = client.post("/v1/sessions", json={"agent_id": "a1"}, headers=HEADERS)
    sid = r.json()["session_id"]

    r = client.post(f"/v1/sessions/{sid}/touch", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["activity_count"] == 1


def test_terminate_session() -> None:
    _reset()
    r = client.post("/v1/sessions", json={"agent_id": "a1"}, headers=HEADERS)
    sid = r.json()["session_id"]

    r = client.post(f"/v1/sessions/{sid}/terminate", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "terminated"


def test_force_logout() -> None:
    _reset()
    client.post("/v1/sessions", json={"agent_id": "a1"}, headers=HEADERS)
    client.post("/v1/sessions", json={"agent_id": "a1"}, headers=HEADERS)

    r = client.post(
        "/v1/sessions/force-logout",
        json={"agent_id": "a1"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["terminated"] == 2


def test_concurrent_session_limit() -> None:
    _reset()
    # Set limit to 2
    client.post(
        "/v1/sessions/policies",
        json={"agent_id": "a1", "max_concurrent": 2},
        headers=HEADERS,
    )

    # Create 2 sessions — OK
    client.post("/v1/sessions", json={"agent_id": "a1"}, headers=HEADERS)
    client.post("/v1/sessions", json={"agent_id": "a1"}, headers=HEADERS)

    # 3rd should fail
    r = client.post("/v1/sessions", json={"agent_id": "a1"}, headers=HEADERS)
    assert r.status_code == 400
    assert "limit" in r.json()["detail"].lower()


def test_session_policy() -> None:
    _reset()
    r = client.post(
        "/v1/sessions/policies",
        json={"agent_id": "a1", "max_concurrent": 3, "default_ttl": 7200},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["max_concurrent"] == 3


def test_get_session_policy() -> None:
    _reset()
    client.post(
        "/v1/sessions/policies",
        json={"agent_id": "a1", "max_concurrent": 10},
        headers=HEADERS,
    )
    r = client.get("/v1/sessions/policies/a1", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["max_concurrent"] == 10


def test_session_stats() -> None:
    _reset()
    client.post("/v1/sessions", json={"agent_id": "a1"}, headers=HEADERS)
    r = client.post("/v1/sessions", json={"agent_id": "a1"}, headers=HEADERS)
    sid = r.json()["session_id"]
    client.post(f"/v1/sessions/{sid}/terminate", headers=HEADERS)

    r = client.get("/v1/sessions/stats?agent_id=a1", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["active"] >= 1
    assert body["terminated"] >= 1


def test_list_filter_by_agent() -> None:
    _reset()
    client.post("/v1/sessions", json={"agent_id": "a1"}, headers=HEADERS)
    client.post("/v1/sessions", json={"agent_id": "a2"}, headers=HEADERS)

    r = client.get("/v1/sessions?agent_id=a1", headers=HEADERS)
    assert r.status_code == 200
    for s in r.json()["sessions"]:
        assert s["agent_id"] == "a1"


if __name__ == "__main__":
    test_create_session()
    test_list_sessions()
    test_get_session()
    test_session_not_found()
    test_touch_session()
    test_terminate_session()
    test_force_logout()
    test_concurrent_session_limit()
    test_session_policy()
    test_get_session_policy()
    test_session_stats()
    test_list_filter_by_agent()
    print("All S146 tests passed!")
