"""S159 — Agent capability quotas tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s159")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s159")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s159")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.capability_quotas import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_create_quota() -> None:
    _reset()
    r = client.post(
        "/v1/quotas",
        json={"agent_id": "a1", "resource": "api_calls", "max_value": 100},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["resource"] == "api_calls"
    assert body["max_value"] == 100
    assert body["enabled"] is True


def test_invalid_resource() -> None:
    _reset()
    r = client.post(
        "/v1/quotas",
        json={"agent_id": "a1", "resource": "invalid", "max_value": 10},
        headers=HEADERS,
    )
    assert r.status_code == 400


def test_get_quota() -> None:
    _reset()
    r = client.post(
        "/v1/quotas",
        json={"agent_id": "a1", "resource": "delegations", "max_value": 50},
        headers=HEADERS,
    )
    qid = r.json()["quota_id"]
    r = client.get(f"/v1/quotas/{qid}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["quota_id"] == qid


def test_quota_not_found() -> None:
    _reset()
    r = client.get("/v1/quotas/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_list_quotas() -> None:
    _reset()
    client.post("/v1/quotas", json={"agent_id": "a1", "resource": "api_calls", "max_value": 100}, headers=HEADERS)
    client.post("/v1/quotas", json={"agent_id": "a2", "resource": "sessions", "max_value": 10}, headers=HEADERS)
    r = client.get("/v1/quotas", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_check_allowed() -> None:
    _reset()
    client.post("/v1/quotas", json={"agent_id": "a1", "resource": "api_calls", "max_value": 10}, headers=HEADERS)
    r = client.post("/v1/quotas/check", json={"agent_id": "a1", "resource": "api_calls"}, headers=HEADERS)
    assert r.json()["allowed"] is True
    assert r.json()["remaining"] == 9


def test_check_no_quota() -> None:
    _reset()
    r = client.post("/v1/quotas/check", json={"agent_id": "a1", "resource": "api_calls"}, headers=HEADERS)
    assert r.json()["allowed"] is True
    assert r.json()["reason"] == "no_quota"


def test_quota_exceeded() -> None:
    _reset()
    client.post("/v1/quotas", json={"agent_id": "a1", "resource": "api_calls", "max_value": 3}, headers=HEADERS)

    for _ in range(3):
        r = client.post("/v1/quotas/check", json={"agent_id": "a1", "resource": "api_calls"}, headers=HEADERS)
        assert r.json()["allowed"] is True

    r = client.post("/v1/quotas/check", json={"agent_id": "a1", "resource": "api_calls"}, headers=HEADERS)
    assert r.json()["allowed"] is False
    assert r.json()["reason"] == "quota_exceeded"


def test_update_quota() -> None:
    _reset()
    r = client.post("/v1/quotas", json={"agent_id": "a1", "resource": "api_calls", "max_value": 10}, headers=HEADERS)
    qid = r.json()["quota_id"]

    r = client.put(f"/v1/quotas/{qid}", json={"max_value": 50}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["max_value"] == 50


def test_get_usage() -> None:
    _reset()
    client.post("/v1/quotas", json={"agent_id": "a1", "resource": "api_calls", "max_value": 10}, headers=HEADERS)
    client.post("/v1/quotas/check", json={"agent_id": "a1", "resource": "api_calls"}, headers=HEADERS)
    client.post("/v1/quotas/check", json={"agent_id": "a1", "resource": "api_calls"}, headers=HEADERS)

    r = client.get("/v1/quotas/usage/a1", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 1
    assert r.json()["usage"][0]["used"] == 2


def test_violations() -> None:
    _reset()
    client.post("/v1/quotas", json={"agent_id": "a1", "resource": "api_calls", "max_value": 1}, headers=HEADERS)
    client.post("/v1/quotas/check", json={"agent_id": "a1", "resource": "api_calls"}, headers=HEADERS)
    client.post("/v1/quotas/check", json={"agent_id": "a1", "resource": "api_calls"}, headers=HEADERS)  # violation

    r = client.get("/v1/quotas/violations", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


def test_stats() -> None:
    _reset()
    client.post("/v1/quotas", json={"agent_id": "a1", "resource": "api_calls", "max_value": 10}, headers=HEADERS)
    r = client.get("/v1/quotas/stats", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total_quotas"] >= 1


if __name__ == "__main__":
    test_create_quota()
    test_invalid_resource()
    test_get_quota()
    test_quota_not_found()
    test_list_quotas()
    test_check_allowed()
    test_check_no_quota()
    test_quota_exceeded()
    test_update_quota()
    test_get_usage()
    test_violations()
    test_stats()
    print("All S159 tests passed!")
