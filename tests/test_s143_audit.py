"""S143 — Audit event streaming and webhook dispatch tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s143")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s143")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s143")
os.environ.setdefault("AGENTHUB_POLICY_SIGNING_SECRET", "test-policy-secret")
os.environ.setdefault("AGENTHUB_VAULT_KEY", "test-vault-key")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.audit_streaming import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_emit_event() -> None:
    _reset()
    r = client.post(
        "/v1/audit/events",
        json={"event_type": "credential.issued", "agent_id": "a1"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["event_type"] == "credential.issued"
    assert body["agent_id"] == "a1"
    assert body["specversion"] == "1.0"
    assert body["severity"] == "info"


def test_emit_invalid_type() -> None:
    _reset()
    r = client.post(
        "/v1/audit/events",
        json={"event_type": "nonexistent.type"},
        headers=HEADERS,
    )
    assert r.status_code == 400


def test_query_events() -> None:
    _reset()
    client.post("/v1/audit/events", json={"event_type": "credential.issued", "agent_id": "a1"}, headers=HEADERS)
    client.post("/v1/audit/events", json={"event_type": "policy.denied", "agent_id": "a2"}, headers=HEADERS)

    r = client.get("/v1/audit/events", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_query_events_filter() -> None:
    _reset()
    client.post("/v1/audit/events", json={"event_type": "credential.issued", "agent_id": "a1"}, headers=HEADERS)
    client.post("/v1/audit/events", json={"event_type": "policy.denied", "agent_id": "a2"}, headers=HEADERS)

    r = client.get("/v1/audit/events?event_type=policy.denied", headers=HEADERS)
    assert r.status_code == 200
    for ev in r.json()["events"]:
        assert ev["event_type"] == "policy.denied"


def test_query_events_by_severity() -> None:
    _reset()
    client.post("/v1/audit/events", json={"event_type": "credential.issued"}, headers=HEADERS)  # info
    client.post("/v1/audit/events", json={"event_type": "anomaly.detected"}, headers=HEADERS)  # critical

    r = client.get("/v1/audit/events?severity=critical", headers=HEADERS)
    assert r.status_code == 200
    for ev in r.json()["events"]:
        assert ev["severity"] == "critical"


def test_register_webhook() -> None:
    _reset()
    r = client.post(
        "/v1/audit/webhooks",
        json={"url": "https://example.com/hook", "secret": "s3cret", "description": "test hook"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["url"] == "https://example.com/hook"
    assert body["secret"] == "***"  # secret masked
    assert body["active"] is True


def test_list_webhooks() -> None:
    _reset()
    client.post("/v1/audit/webhooks", json={"url": "https://a.com/hook"}, headers=HEADERS)
    client.post("/v1/audit/webhooks", json={"url": "https://b.com/hook"}, headers=HEADERS)

    r = client.get("/v1/audit/webhooks", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_deactivate_activate_webhook() -> None:
    _reset()
    r = client.post("/v1/audit/webhooks", json={"url": "https://a.com/hook"}, headers=HEADERS)
    wh_id = r.json()["webhook_id"]

    r = client.post(f"/v1/audit/webhooks/{wh_id}/deactivate", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["active"] is False

    r = client.post(f"/v1/audit/webhooks/{wh_id}/activate", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["active"] is True


def test_webhook_event_dispatch() -> None:
    _reset()
    # Register webhook filtered to credential events
    r = client.post(
        "/v1/audit/webhooks",
        json={"url": "https://a.com/hook", "event_types": ["credential.issued"]},
        headers=HEADERS,
    )
    wh_id = r.json()["webhook_id"]

    # Emit matching event
    client.post("/v1/audit/events", json={"event_type": "credential.issued", "agent_id": "a1"}, headers=HEADERS)

    # Check delivery log
    r = client.get(f"/v1/audit/deliveries?webhook_id={wh_id}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 1
    assert r.json()["deliveries"][0]["status"] == "delivered"


def test_webhook_filter_no_match() -> None:
    _reset()
    # Register webhook only for anomaly events
    r = client.post(
        "/v1/audit/webhooks",
        json={"url": "https://a.com/hook", "event_types": ["anomaly.detected"]},
        headers=HEADERS,
    )
    wh_id = r.json()["webhook_id"]

    # Emit non-matching event
    client.post("/v1/audit/events", json={"event_type": "credential.issued"}, headers=HEADERS)

    # No deliveries for this webhook
    r = client.get(f"/v1/audit/deliveries?webhook_id={wh_id}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] == 0


def test_test_webhook() -> None:
    _reset()
    r = client.post("/v1/audit/webhooks", json={"url": "https://a.com/hook"}, headers=HEADERS)
    wh_id = r.json()["webhook_id"]

    r = client.post(f"/v1/audit/webhooks/{wh_id}/test", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["delivered"] is True


def test_dead_letter_and_retry() -> None:
    _reset()
    # Register webhook
    r = client.post("/v1/audit/webhooks", json={"url": "https://a.com/hook"}, headers=HEADERS)
    wh_id = r.json()["webhook_id"]

    # Emit event
    r = client.post("/v1/audit/events", json={"event_type": "credential.issued"}, headers=HEADERS)
    event_id = r.json()["id"]

    # Simulate failure
    r = client.post(
        "/v1/audit/simulate-failure",
        json={"webhook_id": wh_id, "event_id": event_id},
        headers=HEADERS,
    )
    assert r.status_code == 200
    dl_id = r.json()["dead_letter_id"]

    # Check dead letter queue
    r = client.get("/v1/audit/dead-letters", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 1

    # Retry
    r = client.post(
        "/v1/audit/dead-letters/retry",
        json={"dead_letter_id": dl_id},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["retried"] is True


def test_event_stats() -> None:
    _reset()
    client.post("/v1/audit/events", json={"event_type": "credential.issued", "agent_id": "a1"}, headers=HEADERS)
    client.post("/v1/audit/events", json={"event_type": "policy.denied", "agent_id": "a1"}, headers=HEADERS)
    client.post("/v1/audit/events", json={"event_type": "anomaly.detected", "agent_id": "a2"}, headers=HEADERS)

    r = client.get("/v1/audit/stats", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["total_events"] == 3
    assert body["by_type"]["credential.issued"] == 1
    assert body["by_severity"]["critical"] >= 1


def test_webhook_not_found() -> None:
    _reset()
    r = client.get("/v1/audit/webhooks/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_severity_filter_webhook() -> None:
    _reset()
    # Webhook only for critical events
    r = client.post(
        "/v1/audit/webhooks",
        json={"url": "https://a.com/hook", "severity_filter": "critical"},
        headers=HEADERS,
    )
    wh_id = r.json()["webhook_id"]

    # Emit info event — should not dispatch
    client.post("/v1/audit/events", json={"event_type": "credential.issued"}, headers=HEADERS)
    r = client.get(f"/v1/audit/deliveries?webhook_id={wh_id}", headers=HEADERS)
    assert r.json()["total"] == 0

    # Emit critical event — should dispatch
    client.post("/v1/audit/events", json={"event_type": "anomaly.detected"}, headers=HEADERS)
    r = client.get(f"/v1/audit/deliveries?webhook_id={wh_id}", headers=HEADERS)
    assert r.json()["total"] == 1


if __name__ == "__main__":
    test_emit_event()
    test_emit_invalid_type()
    test_query_events()
    test_query_events_filter()
    test_query_events_by_severity()
    test_register_webhook()
    test_list_webhooks()
    test_deactivate_activate_webhook()
    test_webhook_event_dispatch()
    test_webhook_filter_no_match()
    test_test_webhook()
    test_dead_letter_and_retry()
    test_event_stats()
    test_webhook_not_found()
    test_severity_filter_webhook()
    print("All S143 tests passed!")
