"""S153 — Rate limit policies tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s153")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s153")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s153")
os.environ.setdefault("AGENTHUB_POLICY_SIGNING_SECRET", "test-policy-secret")
os.environ.setdefault("AGENTHUB_VAULT_KEY", "test-vault-key")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.rate_policies import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_create_policy() -> None:
    _reset()
    r = client.post(
        "/v1/rate-policies",
        json={"agent_id": "a1", "max_requests": 100, "window_seconds": 60},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["agent_id"] == "a1"
    assert body["max_requests"] == 100
    assert body["enabled"] is True


def test_get_policy() -> None:
    _reset()
    r = client.post("/v1/rate-policies", json={"agent_id": "a1", "max_requests": 50}, headers=HEADERS)
    pid = r.json()["policy_id"]
    r = client.get(f"/v1/rate-policies/{pid}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["policy_id"] == pid


def test_policy_not_found() -> None:
    _reset()
    r = client.get("/v1/rate-policies/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_list_policies() -> None:
    _reset()
    client.post("/v1/rate-policies", json={"agent_id": "a1", "max_requests": 100}, headers=HEADERS)
    client.post("/v1/rate-policies", json={"agent_id": "a2", "max_requests": 200}, headers=HEADERS)
    r = client.get("/v1/rate-policies", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_list_filter_by_agent() -> None:
    _reset()
    client.post("/v1/rate-policies", json={"agent_id": "a1", "max_requests": 100}, headers=HEADERS)
    client.post("/v1/rate-policies", json={"agent_id": "a2", "max_requests": 200}, headers=HEADERS)
    r = client.get("/v1/rate-policies?agent_id=a1", headers=HEADERS)
    for p in r.json()["policies"]:
        assert p["agent_id"] == "a1"


def test_update_policy() -> None:
    _reset()
    r = client.post("/v1/rate-policies", json={"agent_id": "a1", "max_requests": 100}, headers=HEADERS)
    pid = r.json()["policy_id"]

    r = client.put(f"/v1/rate-policies/{pid}", json={"max_requests": 50}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["max_requests"] == 50


def test_check_allowed() -> None:
    _reset()
    client.post("/v1/rate-policies", json={"agent_id": "a1", "max_requests": 10, "window_seconds": 60}, headers=HEADERS)

    r = client.post("/v1/rate-policies/check", json={"agent_id": "a1"}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["allowed"] is True
    assert r.json()["remaining"] >= 1


def test_check_no_policy() -> None:
    _reset()
    r = client.post("/v1/rate-policies/check", json={"agent_id": "a1"}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["allowed"] is True
    assert r.json()["reason"] == "no_policy"


def test_check_rate_limited() -> None:
    _reset()
    client.post("/v1/rate-policies", json={"agent_id": "a1", "max_requests": 3, "window_seconds": 60}, headers=HEADERS)

    # Use up the quota
    for _ in range(3):
        r = client.post("/v1/rate-policies/check", json={"agent_id": "a1"}, headers=HEADERS)
        assert r.json()["allowed"] is True

    # Next request should be denied
    r = client.post("/v1/rate-policies/check", json={"agent_id": "a1"}, headers=HEADERS)
    assert r.json()["allowed"] is False
    assert r.json()["remaining"] == 0


def test_burst_allowance() -> None:
    _reset()
    client.post(
        "/v1/rate-policies",
        json={"agent_id": "a1", "max_requests": 2, "burst_allowance": 1, "window_seconds": 60},
        headers=HEADERS,
    )

    # Should allow 3 requests (2 + 1 burst)
    for _ in range(3):
        r = client.post("/v1/rate-policies/check", json={"agent_id": "a1"}, headers=HEADERS)
        assert r.json()["allowed"] is True

    r = client.post("/v1/rate-policies/check", json={"agent_id": "a1"}, headers=HEADERS)
    assert r.json()["allowed"] is False


def test_violations() -> None:
    _reset()
    client.post("/v1/rate-policies", json={"agent_id": "a1", "max_requests": 1, "window_seconds": 60}, headers=HEADERS)

    client.post("/v1/rate-policies/check", json={"agent_id": "a1"}, headers=HEADERS)  # allowed
    client.post("/v1/rate-policies/check", json={"agent_id": "a1"}, headers=HEADERS)  # denied

    r = client.get("/v1/rate-policies/violations", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


def test_stats() -> None:
    _reset()
    client.post("/v1/rate-policies", json={"agent_id": "a1", "max_requests": 10}, headers=HEADERS)
    r = client.get("/v1/rate-policies/stats", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["total_policies"] >= 1
    assert body["enabled_policies"] >= 1


if __name__ == "__main__":
    test_create_policy()
    test_get_policy()
    test_policy_not_found()
    test_list_policies()
    test_list_filter_by_agent()
    test_update_policy()
    test_check_allowed()
    test_check_no_policy()
    test_check_rate_limited()
    test_burst_allowance()
    test_violations()
    test_stats()
    print("All S153 tests passed!")
