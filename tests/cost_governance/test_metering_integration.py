from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.cost_governance import storage as cost_storage
from src.delegation import storage as delegation_storage


@pytest.fixture(autouse=True)
def isolate_cost_and_delegation_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    delegation_db = tmp_path / "delegation.db"
    billing_db = tmp_path / "billing.db"
    monkeypatch.setenv("AGENTHUB_COST_EVENTS_PATH", str(tmp_path / "cost-events.json"))
    monkeypatch.setenv("AGENTHUB_COST_DB_PATH", str(billing_db))
    monkeypatch.setenv("AGENTHUB_BILLING_DB_PATH", str(billing_db))
    monkeypatch.setenv("AGENTHUB_DELEGATION_DB_PATH", str(delegation_db))
    cost_storage.reset_for_tests(db_path=billing_db)
    delegation_storage.reset_for_tests(db_path=delegation_db)
    delegation_storage.save_balances(
        {
            "@demo:invoice-summarizer": 1000.0,
            "@demo:support-orchestrator": 1000.0,
        }
    )
    monkeypatch.setenv("AGENTHUB_TRUST_USAGE_EVENTS_PATH", str(tmp_path / "usage-events.json"))


def test_metering_records_search_delegation_and_install_operations() -> None:
    client = TestClient(app)

    search = client.post(
        "/v1/capabilities/search",
        json={"query": "extract invoice totals"},
    )
    assert search.status_code == 200

    delegation = client.post(
        "/v1/delegations",
        json={
            "requester_agent_id": "@demo:invoice-summarizer",
            "delegate_agent_id": "@demo:support-orchestrator",
            "task_spec": "metering check",
            "estimated_cost_usd": 5.0,
            "max_budget_usd": 10.0,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s20-metering-1"},
    )
    assert delegation.status_code == 200

    lease = client.post(
        "/v1/capabilities/lease",
        json={
            "requester_agent_id": "@demo:invoice-summarizer",
            "capability_ref": "@seed:data-normalizer/normalize-records",
            "ttl_seconds": 600,
        },
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert lease.status_code == 200
    lease_payload = lease.json()

    promote = client.post(
        f"/v1/capabilities/leases/{lease_payload['lease_id']}/promote",
        json={
            "attestation_hash": lease_payload["attestation_hash"],
            "signature": f"sig:{lease_payload['attestation_hash']}:owner-dev",
            "policy_approved": True,
            "approval_ticket": "APR-2001",
            "compatibility_verified": True,
        },
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert promote.status_code == 200

    events = client.get("/v1/cost/metering", headers={"X-API-Key": "dev-owner-key"})
    assert events.status_code == 200
    operations = {row["operation"] for row in events.json()["data"]}
    assert "capabilities.search" in operations
    assert "delegation.create" in operations
    assert "capabilities.lease_promote" in operations


def test_budget_hard_stop_cannot_be_bypassed() -> None:
    client = TestClient(app)
    denied = client.post(
        "/v1/delegations",
        json={
            "requester_agent_id": "@demo:invoice-summarizer",
            "delegate_agent_id": "@demo:support-orchestrator",
            "task_spec": "overrun",
            "estimated_cost_usd": 50.0,
            "max_budget_usd": 20.0,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s20-hard-stop-1"},
    )
    assert denied.status_code == 400
    detail = denied.json()["detail"]["policy_decision"]
    assert "budget.hard_stop_120" in detail["violated_constraints"]
