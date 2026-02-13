from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.delegation import storage as delegation_storage
from src.reliability.service import build_slo_dashboard


@pytest.fixture(autouse=True)
def isolate_reliability_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "delegation.db"
    monkeypatch.setenv("AGENTHUB_DELEGATION_DB_PATH", str(db_path))
    monkeypatch.setenv("AGENTHUB_TRUST_USAGE_EVENTS_PATH", str(tmp_path / "usage_events.json"))
    delegation_storage.reset_for_tests(db_path=db_path)
    delegation_storage.save_balances(
        {
            "@demo:invoice-summarizer": 1000.0,
            "@demo:support-orchestrator": 1000.0,
        }
    )


def _seed_delegation_record(idx: int, status: str, latency_ms: float) -> None:
    timestamp_base = f"2026-02-12T01:{idx:02d}:00Z"
    delegation_storage.append_record(
        {
            "delegation_id": f"dlg-s37-{idx}",
            "requester_agent_id": "@demo:invoice-summarizer",
            "delegate_agent_id": "@demo:support-orchestrator",
            "task_spec": "Synthetic S37 reliability sample",
            "estimated_cost_usd": 10.0,
            "actual_cost_usd": 8.0,
            "max_budget_usd": 20.0,
            "status": status,
            "budget_controls": {"state": "ok"},
            "audit_trail": [],
            "lifecycle": [
                {"stage": "discovery", "timestamp": timestamp_base, "details": {}},
                {
                    "stage": "delivery",
                    "timestamp": timestamp_base,
                    "details": {"latency_ms": latency_ms},
                },
            ],
            "created_at": timestamp_base,
            "updated_at": timestamp_base,
        }
    )


def test_slo_dashboard_closed_for_healthy_load() -> None:
    for idx in range(20):
        _seed_delegation_record(idx=idx, status="completed", latency_ms=420.0)

    dashboard = build_slo_dashboard(window_size=20)
    assert dashboard["metrics"]["success_rate"] == 1.0
    assert dashboard["metrics"]["latency_p95_ms"] == 420.0
    assert dashboard["circuit_breaker"]["state"] == "closed"
    assert dashboard["alerts"] == []


def test_slo_dashboard_emits_alerts_and_opens_breaker_under_chaos_load() -> None:
    for idx in range(12):
        _seed_delegation_record(idx=idx, status="failed_hard_stop", latency_ms=6100.0)
    for idx in range(12, 20):
        _seed_delegation_record(idx=idx, status="completed", latency_ms=5200.0)

    dashboard = build_slo_dashboard(window_size=20)
    alert_codes = {row["code"] for row in dashboard["alerts"]}
    assert dashboard["circuit_breaker"]["state"] == "open"
    assert dashboard["error_budget"]["consumed_ratio"] >= 1.0
    assert "error_budget.exhausted" in alert_codes
    assert "latency.slo_critical" in alert_codes
    assert "circuit_breaker.hard_stop_rate" in alert_codes


def test_delegation_api_rejects_new_requests_when_breaker_open() -> None:
    for idx in range(15):
        _seed_delegation_record(idx=idx, status="failed_hard_stop", latency_ms=5500.0)

    with TestClient(app) as c:
        dashboard = c.get("/v1/reliability/slo-dashboard", headers={"X-API-Key": "dev-owner-key"})
        assert dashboard.status_code == 200
        assert dashboard.json()["circuit_breaker"]["state"] == "open"

        blocked = c.post(
            "/v1/delegations",
            json={
                "requester_agent_id": "@demo:invoice-summarizer",
                "delegate_agent_id": "@demo:support-orchestrator",
                "task_spec": "Should be blocked by open breaker",
                "estimated_cost_usd": 10.0,
                "max_budget_usd": 20.0,
                "simulated_actual_cost_usd": 8.0,
            },
            headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s37-breaker-open-1"},
        )
        assert blocked.status_code == 503
        detail = blocked.json()["detail"]
        assert detail["circuit_breaker"]["state"] == "open"
        assert detail["message"] == "delegation circuit breaker is open"
