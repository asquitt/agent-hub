"""S140 — Intent-aware access logging tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s140")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s140")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s140")
os.environ.setdefault("AGENTHUB_POLICY_SIGNING_SECRET", "test-policy-secret")
os.environ.setdefault("AGENTHUB_VAULT_KEY", "test-vault-key")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.intent_logging import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_log_access() -> None:
    _reset()
    r = client.post(
        "/v1/intent/log",
        json={"agent_id": "a1", "action": "read_data", "intent": "data_access"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["agent_id"] == "a1"
    assert body["intent"] == "data_access"
    assert body["drift_detected"] is False


def test_log_with_drift_detection() -> None:
    _reset()
    r = client.post(
        "/v1/intent/log",
        json={"agent_id": "a1", "action": "delete_records", "intent": "data_access"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["drift_detected"] is True
    assert "privileged action" in body["drift_detail"]


def test_query_access_log() -> None:
    _reset()
    client.post(
        "/v1/intent/log",
        json={"agent_id": "a1", "action": "read_x", "intent": "data_access"},
        headers=HEADERS,
    )
    client.post(
        "/v1/intent/log",
        json={"agent_id": "a2", "action": "write_y", "intent": "administration"},
        headers=HEADERS,
    )
    r = client.get("/v1/intent/log", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_query_filter_by_agent() -> None:
    _reset()
    client.post(
        "/v1/intent/log",
        json={"agent_id": "a1", "action": "op1", "intent": "monitoring"},
        headers=HEADERS,
    )
    client.post(
        "/v1/intent/log",
        json={"agent_id": "a2", "action": "op2", "intent": "monitoring"},
        headers=HEADERS,
    )
    r = client.get("/v1/intent/log?agent_id=a1", headers=HEADERS)
    assert r.status_code == 200
    for entry in r.json()["entries"]:
        assert entry["agent_id"] == "a1"


def test_intent_summary() -> None:
    _reset()
    client.post(
        "/v1/intent/log",
        json={"agent_id": "a1", "action": "read_data", "intent": "data_access"},
        headers=HEADERS,
    )
    client.post(
        "/v1/intent/log",
        json={"agent_id": "a1", "action": "check_health", "intent": "monitoring"},
        headers=HEADERS,
    )
    r = client.get("/v1/intent/summary/a1", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["total_events"] == 2
    assert "data_access" in body["intent_distribution"]
    assert "monitoring" in body["intent_distribution"]


def test_evaluate_intent_allowed() -> None:
    _reset()
    r = client.post(
        "/v1/intent/evaluate",
        json={"agent_id": "a1", "intent": "data_access"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["allowed"] is True


def test_intent_policy_enforcement() -> None:
    _reset()
    # Set policy restricting agent to only monitoring
    client.post(
        "/v1/intent/policies",
        json={"agent_id": "a1", "allowed_intents": ["monitoring"]},
        headers=HEADERS,
    )
    # Try data_access
    r = client.post(
        "/v1/intent/evaluate",
        json={"agent_id": "a1", "intent": "data_access"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["allowed"] is False


def test_justification_required_policy() -> None:
    _reset()
    client.post(
        "/v1/intent/policies",
        json={"agent_id": "a1", "required_justification": True},
        headers=HEADERS,
    )
    # Without justification
    r = client.post(
        "/v1/intent/evaluate",
        json={"agent_id": "a1", "intent": "data_access"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["allowed"] is False

    # With justification
    r = client.post(
        "/v1/intent/evaluate",
        json={"agent_id": "a1", "intent": "data_access", "justification": "JIRA-123"},
        headers=HEADERS,
    )
    assert r.json()["allowed"] is True


def test_max_risk_score_policy() -> None:
    _reset()
    client.post(
        "/v1/intent/policies",
        json={"max_risk_score": 15},
        headers=HEADERS,
    )
    # Monitoring (risk=10) should pass
    r = client.post(
        "/v1/intent/evaluate",
        json={"agent_id": "a1", "intent": "monitoring"},
        headers=HEADERS,
    )
    assert r.json()["allowed"] is True

    # Data access (risk=20) should fail
    r = client.post(
        "/v1/intent/evaluate",
        json={"agent_id": "a1", "intent": "data_access"},
        headers=HEADERS,
    )
    assert r.json()["allowed"] is False


def test_list_policies() -> None:
    _reset()
    client.post(
        "/v1/intent/policies",
        json={"allowed_intents": ["monitoring"]},
        headers=HEADERS,
    )
    r = client.get("/v1/intent/policies", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


def test_empty_summary() -> None:
    _reset()
    r = client.get("/v1/intent/summary/nonexistent", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total_events"] == 0


if __name__ == "__main__":
    test_log_access()
    test_log_with_drift_detection()
    test_query_access_log()
    test_query_filter_by_agent()
    test_intent_summary()
    test_evaluate_intent_allowed()
    test_intent_policy_enforcement()
    test_justification_required_policy()
    test_max_risk_score_policy()
    test_list_policies()
    test_empty_summary()
    print("All S140 tests passed!")
