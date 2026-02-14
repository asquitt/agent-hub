"""S145 — Policy-as-Code declarative rule engine tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s145")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s145")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s145")

from fastapi.testclient import TestClient

from src.api.app import app
from src.policy.policy_as_code import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_create_rule() -> None:
    _reset()
    r = client.post(
        "/v1/policy/rules",
        json={"name": "deny-admin", "effect": "deny", "target_actions": ["admin_*"]},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "deny-admin"
    assert body["effect"] == "deny"
    assert body["version"] == 1


def test_list_rules() -> None:
    _reset()
    client.post("/v1/policy/rules", json={"name": "r1", "effect": "allow"}, headers=HEADERS)
    client.post("/v1/policy/rules", json={"name": "r2", "effect": "deny"}, headers=HEADERS)
    r = client.get("/v1/policy/rules", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_get_rule() -> None:
    _reset()
    r = client.post("/v1/policy/rules", json={"name": "r1", "effect": "allow"}, headers=HEADERS)
    rule_id = r.json()["rule_id"]
    r = client.get(f"/v1/policy/rules/{rule_id}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["rule_id"] == rule_id


def test_update_rule() -> None:
    _reset()
    r = client.post("/v1/policy/rules", json={"name": "r1", "effect": "allow"}, headers=HEADERS)
    rule_id = r.json()["rule_id"]

    r = client.put(
        f"/v1/policy/rules/{rule_id}",
        json={"effect": "deny", "priority": 200},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["effect"] == "deny"
    assert r.json()["version"] == 2


def test_delete_rule() -> None:
    _reset()
    r = client.post("/v1/policy/rules", json={"name": "r1", "effect": "allow"}, headers=HEADERS)
    rule_id = r.json()["rule_id"]

    r = client.delete(f"/v1/policy/rules/{rule_id}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["deleted"] is True


def test_rule_not_found() -> None:
    _reset()
    r = client.get("/v1/policy/rules/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_evaluate_default_allow() -> None:
    _reset()
    r = client.post(
        "/v1/policy/evaluate",
        json={"agent_id": "a1", "action": "read_data"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "allow"


def test_evaluate_deny_rule() -> None:
    _reset()
    # Create deny rule for admin actions
    client.post(
        "/v1/policy/rules",
        json={"name": "deny-admin", "effect": "deny", "target_actions": ["admin_*"]},
        headers=HEADERS,
    )

    r = client.post(
        "/v1/policy/evaluate",
        json={"agent_id": "a1", "action": "admin_delete"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "deny"
    assert len(r.json()["matched_rules"]) >= 1


def test_evaluate_agent_specific_rule() -> None:
    _reset()
    # Deny agent-x from everything
    client.post(
        "/v1/policy/rules",
        json={"name": "block-agent-x", "effect": "deny", "target_agents": ["agent-x"]},
        headers=HEADERS,
    )

    # agent-x is denied
    r = client.post(
        "/v1/policy/evaluate",
        json={"agent_id": "agent-x", "action": "read"},
        headers=HEADERS,
    )
    assert r.json()["decision"] == "deny"

    # agent-y is allowed
    r = client.post(
        "/v1/policy/evaluate",
        json={"agent_id": "agent-y", "action": "read"},
        headers=HEADERS,
    )
    assert r.json()["decision"] == "allow"


def test_evaluate_with_conditions() -> None:
    _reset()
    # Deny if risk_score > 80
    client.post(
        "/v1/policy/rules",
        json={
            "name": "high-risk-deny",
            "effect": "deny",
            "conditions": [{"attribute": "risk_score", "operator": "greater_than", "value": 80}],
        },
        headers=HEADERS,
    )

    # Low risk = allow
    r = client.post(
        "/v1/policy/evaluate",
        json={"agent_id": "a1", "action": "read", "context": {"risk_score": 30}},
        headers=HEADERS,
    )
    assert r.json()["decision"] == "allow"

    # High risk = deny
    r = client.post(
        "/v1/policy/evaluate",
        json={"agent_id": "a1", "action": "read", "context": {"risk_score": 95}},
        headers=HEADERS,
    )
    assert r.json()["decision"] == "deny"


def test_evaluate_require_approval() -> None:
    _reset()
    client.post(
        "/v1/policy/rules",
        json={"name": "approve-write", "effect": "require_approval", "target_actions": ["write_*"]},
        headers=HEADERS,
    )

    r = client.post(
        "/v1/policy/evaluate",
        json={"agent_id": "a1", "action": "write_data"},
        headers=HEADERS,
    )
    assert r.json()["decision"] == "require_approval"


def test_dry_run_no_log() -> None:
    _reset()
    r = client.post(
        "/v1/policy/evaluate",
        json={"agent_id": "a1", "action": "read", "dry_run": True},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["dry_run"] is True

    # No evaluations logged
    r = client.get("/v1/policy/evaluations", headers=HEADERS)
    assert r.json()["total"] == 0


def test_evaluation_log() -> None:
    _reset()
    client.post("/v1/policy/evaluate", json={"agent_id": "a1", "action": "read"}, headers=HEADERS)
    client.post("/v1/policy/evaluate", json={"agent_id": "a2", "action": "write"}, headers=HEADERS)

    r = client.get("/v1/policy/evaluations", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_rule_versions() -> None:
    _reset()
    r = client.post("/v1/policy/rules", json={"name": "r1", "effect": "allow"}, headers=HEADERS)
    rule_id = r.json()["rule_id"]

    client.put(f"/v1/policy/rules/{rule_id}", json={"effect": "deny"}, headers=HEADERS)

    r = client.get(f"/v1/policy/rules/{rule_id}/versions", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_priority_ordering() -> None:
    _reset()
    # Low priority allow
    client.post(
        "/v1/policy/rules",
        json={"name": "allow-all", "effect": "allow", "priority": 50},
        headers=HEADERS,
    )
    # High priority deny
    client.post(
        "/v1/policy/rules",
        json={"name": "deny-all", "effect": "deny", "priority": 200},
        headers=HEADERS,
    )

    r = client.post(
        "/v1/policy/evaluate",
        json={"agent_id": "a1", "action": "read"},
        headers=HEADERS,
    )
    # Deny wins because it matches first (higher priority)
    assert r.json()["decision"] == "deny"


if __name__ == "__main__":
    test_create_rule()
    test_list_rules()
    test_get_rule()
    test_update_rule()
    test_delete_rule()
    test_rule_not_found()
    test_evaluate_default_allow()
    test_evaluate_deny_rule()
    test_evaluate_agent_specific_rule()
    test_evaluate_with_conditions()
    test_evaluate_require_approval()
    test_dry_run_no_log()
    test_evaluation_log()
    test_rule_versions()
    test_priority_ordering()
    print("All S145 tests passed!")
