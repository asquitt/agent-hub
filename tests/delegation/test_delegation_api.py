from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import DELEGATION_IDEMPOTENCY_CACHE, app
from src.delegation import storage as delegation_storage


@pytest.fixture(autouse=True)
def isolate_delegation_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "delegation.db"
    monkeypatch.setenv("AGENTHUB_DELEGATION_DB_PATH", str(db_path))
    delegation_storage.reset_for_tests(db_path=db_path)
    delegation_storage.save_balances(
        {
            "@demo:invoice-summarizer": 1000.0,
            "@demo:support-orchestrator": 1000.0,
        }
    )
    monkeypatch.setenv("AGENTHUB_TRUST_USAGE_EVENTS_PATH", str(tmp_path / "usage_events.json"))
    DELEGATION_IDEMPOTENCY_CACHE.clear()


def client() -> TestClient:
    return TestClient(app)


def test_full_delegation_lifecycle_and_audit_trail() -> None:
    with TestClient(app) as c:
        response = c.post(
            "/v1/delegations",
            json={
                "requester_agent_id": "@demo:invoice-summarizer",
                "delegate_agent_id": "@demo:support-orchestrator",
                "task_spec": "Classify and remediate ticket",
                "estimated_cost_usd": 10,
                "max_budget_usd": 20,
                "simulated_actual_cost_usd": 8,
            },
            headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "delegation-lifecycle-1"},
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "completed"
        assert payload["policy_decision"]["decision"] == "allow"
        stages = [s["stage"] for s in payload["lifecycle"]]
        assert stages == ["discovery", "negotiation", "execution", "delivery", "settlement", "feedback"]

        delegation_id = payload["delegation_id"]
        status = c.get(f"/v1/delegations/{delegation_id}/status")
        assert status.status_code == 200
        status_payload = status.json()
        assert status_payload["budget_controls"]["soft_alert"] is True
        assert status_payload["audit_trail"]
        assert status_payload["policy_decision"]["decision"] == "allow"


def test_budget_hard_ceiling_rejects_request() -> None:
    with TestClient(app) as c:
        response = c.post(
            "/v1/delegations",
            json={
                "requester_agent_id": "@demo:invoice-summarizer",
                "delegate_agent_id": "@demo:support-orchestrator",
                "task_spec": "Overbudget task",
                "estimated_cost_usd": 50,
                "max_budget_usd": 20,
            },
            headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "delegation-budget-hardceiling-1"},
        )
        assert response.status_code == 400
        detail = response.json()["detail"]
        assert detail["policy_decision"]["decision"] == "deny"
        assert "budget.hard_stop_120" in detail["policy_decision"]["violated_constraints"]


def test_circuit_breakers_100_and_120_thresholds() -> None:
    with TestClient(app) as c:
        at_100 = c.post(
            "/v1/delegations",
            json={
                "requester_agent_id": "@demo:invoice-summarizer",
                "delegate_agent_id": "@demo:support-orchestrator",
                "task_spec": "Needs reauth",
                "estimated_cost_usd": 10,
                "max_budget_usd": 20,
                "simulated_actual_cost_usd": 10,
                "auto_reauthorize": False,
            },
            headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "delegation-circuit-100"},
        )
        assert at_100.status_code == 200
        assert at_100.json()["status"] == "pending_reauthorization"
        assert at_100.json()["budget_controls"]["reauthorization_required"] is True

        at_120 = c.post(
            "/v1/delegations",
            json={
                "requester_agent_id": "@demo:invoice-summarizer",
                "delegate_agent_id": "@demo:support-orchestrator",
                "task_spec": "Should hard stop",
                "estimated_cost_usd": 10,
                "max_budget_usd": 20,
                "simulated_actual_cost_usd": 12.5,
            },
            headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "delegation-circuit-120"},
        )
        assert at_120.status_code == 200
        assert at_120.json()["status"] == "failed_hard_stop"
        assert at_120.json()["budget_controls"]["hard_stop"] is True


def test_policy_boundary_enforces_trust_and_permissions() -> None:
    with TestClient(app) as c:
        blocked = c.post(
            "/v1/delegations",
            json={
                "requester_agent_id": "@demo:invoice-summarizer",
                "delegate_agent_id": "@demo:support-orchestrator",
                "task_spec": "Run payment",
                "estimated_cost_usd": 5,
                "max_budget_usd": 20,
                "min_delegate_trust_score": 0.9,
                "required_permissions": ["payments.execute"],
            },
            headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "delegation-policy-boundary-1"},
        )
        assert blocked.status_code == 403
        detail = blocked.json()["detail"]
        assert detail["policy_decision"]["decision"] == "deny"
        assert "trust.floor_not_met" in detail["policy_decision"]["violated_constraints"]
        assert "permissions.missing_required" in detail["policy_decision"]["violated_constraints"]


def test_delegation_idempotent_replay_returns_same_response() -> None:
    payload = {
        "requester_agent_id": "@demo:invoice-summarizer",
        "delegate_agent_id": "@demo:support-orchestrator",
        "task_spec": "Classify and remediate ticket",
        "estimated_cost_usd": 10,
        "max_budget_usd": 20,
        "simulated_actual_cost_usd": 8,
    }
    headers = {"X-API-Key": "dev-owner-key", "Idempotency-Key": "delegation-replay-1"}
    with TestClient(app) as c:
        first = c.post("/v1/delegations", json=payload, headers=headers)
        second = c.post("/v1/delegations", json=payload, headers=headers)
        assert first.status_code == 200
        assert second.status_code == 200
        assert first.json() == second.json()


def test_delegation_idempotency_key_reuse_with_different_payload_rejected() -> None:
    with TestClient(app) as c:
        first = c.post(
            "/v1/delegations",
            json={
                "requester_agent_id": "@demo:invoice-summarizer",
                "delegate_agent_id": "@demo:support-orchestrator",
                "task_spec": "Task A",
                "estimated_cost_usd": 8,
                "max_budget_usd": 20,
            },
            headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "delegation-replay-2"},
        )
        assert first.status_code == 200

        second = c.post(
            "/v1/delegations",
            json={
                "requester_agent_id": "@demo:invoice-summarizer",
                "delegate_agent_id": "@demo:support-orchestrator",
                "task_spec": "Task B",
                "estimated_cost_usd": 9,
                "max_budget_usd": 20,
            },
            headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "delegation-replay-2"},
        )
        assert second.status_code == 409


def test_delegation_contract_v2_endpoint() -> None:
    with TestClient(app) as c:
        response = c.get("/v1/delegations/contract", headers={"X-API-Key": "dev-owner-key"})
        assert response.status_code == 200
        payload = response.json()
        assert payload["version"] == "delegation-contract-v2"
        assert payload["idempotency_required"] is True
        assert payload["sla"]["p95_latency_ms_target"] == 3000
