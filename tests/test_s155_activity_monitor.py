"""S155 — Agent activity monitoring tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s155")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s155")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s155")
os.environ.setdefault("AGENTHUB_POLICY_SIGNING_SECRET", "test-policy-secret")
os.environ.setdefault("AGENTHUB_VAULT_KEY", "test-vault-key")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.activity_monitor import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_record_activity() -> None:
    _reset()
    r = client.post(
        "/v1/activity",
        json={"agent_id": "a1", "action": "api_call", "resource": "/v1/agents"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["agent_id"] == "a1"
    assert body["action"] == "api_call"
    assert body["activity_id"].startswith("act-")


def test_get_activity() -> None:
    _reset()
    r = client.post(
        "/v1/activity",
        json={"agent_id": "a1", "action": "read"},
        headers=HEADERS,
    )
    aid = r.json()["activity_id"]
    r = client.get(f"/v1/activity/{aid}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["activity_id"] == aid


def test_activity_not_found() -> None:
    _reset()
    r = client.get("/v1/activity/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_list_activities() -> None:
    _reset()
    client.post("/v1/activity", json={"agent_id": "a1", "action": "read"}, headers=HEADERS)
    client.post("/v1/activity", json={"agent_id": "a2", "action": "write"}, headers=HEADERS)
    r = client.get("/v1/activity", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_list_filter_by_agent() -> None:
    _reset()
    client.post("/v1/activity", json={"agent_id": "a1", "action": "read"}, headers=HEADERS)
    client.post("/v1/activity", json={"agent_id": "a2", "action": "write"}, headers=HEADERS)
    r = client.get("/v1/activity?agent_id=a1", headers=HEADERS)
    assert r.status_code == 200
    for act in r.json()["activities"]:
        assert act["agent_id"] == "a1"


def test_agent_summary() -> None:
    _reset()
    client.post("/v1/activity", json={"agent_id": "a1", "action": "read"}, headers=HEADERS)
    client.post("/v1/activity", json={"agent_id": "a1", "action": "write"}, headers=HEADERS)
    client.post("/v1/activity", json={"agent_id": "a1", "action": "read"}, headers=HEADERS)

    r = client.get("/v1/activity/summary/a1", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["total_activities"] == 3
    assert body["actions"]["read"] == 2
    assert body["actions"]["write"] == 1


def test_agent_summary_empty() -> None:
    _reset()
    r = client.get("/v1/activity/summary/nobody", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total_activities"] == 0


def test_create_alert() -> None:
    _reset()
    r = client.post(
        "/v1/activity/alerts",
        json={"agent_id": "a1", "alert_type": "suspicious", "severity": "high", "message": "test alert"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["alert_type"] == "suspicious"
    assert body["status"] == "open"


def test_invalid_severity() -> None:
    _reset()
    r = client.post(
        "/v1/activity/alerts",
        json={"agent_id": "a1", "alert_type": "x", "severity": "invalid", "message": "test"},
        headers=HEADERS,
    )
    assert r.status_code == 400


def test_get_alert() -> None:
    _reset()
    r = client.post(
        "/v1/activity/alerts",
        json={"agent_id": "a1", "alert_type": "x", "severity": "low", "message": "test"},
        headers=HEADERS,
    )
    alert_id = r.json()["alert_id"]
    r = client.get(f"/v1/activity/alerts/{alert_id}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["alert_id"] == alert_id


def test_alert_not_found() -> None:
    _reset()
    r = client.get("/v1/activity/alerts/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_acknowledge_alert() -> None:
    _reset()
    r = client.post(
        "/v1/activity/alerts",
        json={"agent_id": "a1", "alert_type": "x", "severity": "medium", "message": "test"},
        headers=HEADERS,
    )
    alert_id = r.json()["alert_id"]
    r = client.post(f"/v1/activity/alerts/{alert_id}/acknowledge", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "acknowledged"


def test_list_alerts() -> None:
    _reset()
    client.post(
        "/v1/activity/alerts",
        json={"agent_id": "a1", "alert_type": "x", "severity": "low", "message": "t1"},
        headers=HEADERS,
    )
    client.post(
        "/v1/activity/alerts",
        json={"agent_id": "a2", "alert_type": "y", "severity": "high", "message": "t2"},
        headers=HEADERS,
    )
    r = client.get("/v1/activity/alerts", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_stats() -> None:
    _reset()
    client.post("/v1/activity", json={"agent_id": "a1", "action": "read"}, headers=HEADERS)
    client.post(
        "/v1/activity/alerts",
        json={"agent_id": "a1", "alert_type": "x", "severity": "low", "message": "t"},
        headers=HEADERS,
    )
    r = client.get("/v1/activity/stats", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["total_activities"] >= 1
    assert body["total_alerts"] >= 1


if __name__ == "__main__":
    test_record_activity()
    test_get_activity()
    test_activity_not_found()
    test_list_activities()
    test_list_filter_by_agent()
    test_agent_summary()
    test_agent_summary_empty()
    test_create_alert()
    test_invalid_severity()
    test_get_alert()
    test_alert_not_found()
    test_acknowledge_alert()
    test_list_alerts()
    test_stats()
    print("All S155 tests passed!")
