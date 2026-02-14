"""S139 — Human-in-the-loop approval workflow tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s139")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s139")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s139")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.approval import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_create_approval_request() -> None:
    _reset()
    r = client.post(
        "/v1/approval/requests",
        json={"agent_id": "agent-1", "action": "read_data"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["agent_id"] == "agent-1"
    assert body["action"] == "read_data"
    assert body["risk_level"] == "low"
    # Low risk = auto-approved by default
    assert body["status"] == "auto_approved"


def test_create_high_risk_requires_approval() -> None:
    _reset()
    r = client.post(
        "/v1/approval/requests",
        json={"agent_id": "agent-1", "action": "delete_records"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["risk_level"] == "high"
    assert body["status"] == "pending"


def test_decide_approval() -> None:
    _reset()
    # Create a pending request
    r = client.post(
        "/v1/approval/requests",
        json={"agent_id": "agent-1", "action": "admin_access"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    request_id = r.json()["request_id"]
    assert r.json()["status"] == "pending"

    # Approve it
    r = client.post(
        f"/v1/approval/requests/{request_id}/decide",
        json={"decision": "approve", "reason": "authorized by admin"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "approved"


def test_reject_approval() -> None:
    _reset()
    r = client.post(
        "/v1/approval/requests",
        json={"agent_id": "agent-1", "action": "revoke_all"},
        headers=HEADERS,
    )
    request_id = r.json()["request_id"]

    r = client.post(
        f"/v1/approval/requests/{request_id}/decide",
        json={"decision": "reject", "reason": "not authorized"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "rejected"


def test_cannot_decide_twice() -> None:
    _reset()
    r = client.post(
        "/v1/approval/requests",
        json={"agent_id": "agent-1", "action": "delete_data"},
        headers=HEADERS,
    )
    request_id = r.json()["request_id"]

    client.post(
        f"/v1/approval/requests/{request_id}/decide",
        json={"decision": "approve"},
        headers=HEADERS,
    )
    # Try again
    r = client.post(
        f"/v1/approval/requests/{request_id}/decide",
        json={"decision": "reject"},
        headers=HEADERS,
    )
    assert r.status_code == 400


def test_list_requests() -> None:
    _reset()
    client.post(
        "/v1/approval/requests",
        json={"agent_id": "agent-1", "action": "delete_x"},
        headers=HEADERS,
    )
    client.post(
        "/v1/approval/requests",
        json={"agent_id": "agent-2", "action": "read_y"},
        headers=HEADERS,
    )
    r = client.get("/v1/approval/requests", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_list_filter_by_status() -> None:
    _reset()
    client.post(
        "/v1/approval/requests",
        json={"agent_id": "agent-1", "action": "admin_op"},
        headers=HEADERS,
    )
    r = client.get("/v1/approval/requests?status=pending", headers=HEADERS)
    assert r.status_code == 200
    for req in r.json()["requests"]:
        assert req["status"] == "pending"


def test_check_approval() -> None:
    _reset()
    r = client.post(
        "/v1/approval/check",
        json={"agent_id": "agent-1", "action": "read_data"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["approved"] is True  # low risk = auto


def test_check_needs_approval() -> None:
    _reset()
    r = client.post(
        "/v1/approval/check",
        json={"agent_id": "agent-1", "action": "delete_records"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["approved"] is False
    assert body["requires_request"] is True


def test_pending_count() -> None:
    _reset()
    client.post(
        "/v1/approval/requests",
        json={"agent_id": "agent-1", "action": "admin_access"},
        headers=HEADERS,
    )
    r = client.get("/v1/approval/pending", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["pending"] >= 1


def test_set_policy() -> None:
    _reset()
    r = client.post(
        "/v1/approval/policies",
        json={"agent_id": "agent-1", "decision": "auto_approve"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "auto_approve"


def test_policy_overrides_default() -> None:
    _reset()
    # Set policy to auto-approve for agent-1
    client.post(
        "/v1/approval/policies",
        json={"agent_id": "agent-1", "decision": "auto_approve"},
        headers=HEADERS,
    )
    # Now admin actions should auto-approve
    r = client.post(
        "/v1/approval/requests",
        json={"agent_id": "agent-1", "action": "admin_access"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["status"] == "auto_approved"


def test_list_policies() -> None:
    _reset()
    client.post(
        "/v1/approval/policies",
        json={"decision": "deny", "risk_level": "critical"},
        headers=HEADERS,
    )
    r = client.get("/v1/approval/policies", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


def test_get_request_detail() -> None:
    _reset()
    r = client.post(
        "/v1/approval/requests",
        json={"agent_id": "a1", "action": "deploy_new"},
        headers=HEADERS,
    )
    request_id = r.json()["request_id"]
    r = client.get(f"/v1/approval/requests/{request_id}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["request_id"] == request_id


def test_get_request_not_found() -> None:
    _reset()
    r = client.get("/v1/approval/requests/nonexistent", headers=HEADERS)
    assert r.status_code == 404


if __name__ == "__main__":
    test_create_approval_request()
    test_create_high_risk_requires_approval()
    test_decide_approval()
    test_reject_approval()
    test_cannot_decide_twice()
    test_list_requests()
    test_list_filter_by_status()
    test_check_approval()
    test_check_needs_approval()
    test_pending_count()
    test_set_policy()
    test_policy_overrides_default()
    test_list_policies()
    test_get_request_detail()
    test_get_request_not_found()
    print("All S139 tests passed!")
