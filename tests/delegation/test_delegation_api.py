from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app


@pytest.fixture(autouse=True)
def isolate_delegation_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    records = tmp_path / "records.json"
    balances = tmp_path / "balances.json"
    balances.write_text(
        json.dumps(
            [
                {"agent_id": "@demo:invoice-summarizer", "balance_usd": 1000.0},
                {"agent_id": "@demo:support-orchestrator", "balance_usd": 1000.0},
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("AGENTHUB_DELEGATION_RECORDS_PATH", str(records))
    monkeypatch.setenv("AGENTHUB_DELEGATION_BALANCES_PATH", str(balances))
    monkeypatch.setenv("AGENTHUB_TRUST_USAGE_EVENTS_PATH", str(tmp_path / "usage_events.json"))


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
            headers={"X-API-Key": "dev-owner-key"},
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "completed"
        stages = [s["stage"] for s in payload["lifecycle"]]
        assert stages == ["discovery", "negotiation", "execution", "delivery", "settlement", "feedback"]

        delegation_id = payload["delegation_id"]
        status = c.get(f"/v1/delegations/{delegation_id}/status")
        assert status.status_code == 200
        status_payload = status.json()
        assert status_payload["budget_controls"]["soft_alert"] is True
        assert status_payload["audit_trail"]


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
            headers={"X-API-Key": "dev-owner-key"},
        )
        assert response.status_code == 400
        assert "hard ceiling" in response.json()["detail"]


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
            headers={"X-API-Key": "dev-owner-key"},
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
            headers={"X-API-Key": "dev-owner-key"},
        )
        assert at_120.status_code == 200
        assert at_120.json()["status"] == "failed_hard_stop"
        assert at_120.json()["budget_controls"]["hard_stop"] is True
