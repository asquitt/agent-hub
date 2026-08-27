from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.billing import service as billing_service
from src.cost_governance import storage as cost_storage
from src.delegation import storage as delegation_storage

DISABLED_RESPONSE = {
    "detail": {
        "code": "financial.disabled",
        "message": "unproven financial mutations are disabled",
    }
}


@pytest.fixture()
def contained_financial_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Path]:
    billing_db = tmp_path / "billing.db"
    delegation_db = tmp_path / "delegation.db"
    marketplace_db = tmp_path / "marketplace.db"
    procurement_db = tmp_path / "procurement.db"

    monkeypatch.setenv("AGENTHUB_BILLING_DB_PATH", str(billing_db))
    monkeypatch.setenv("AGENTHUB_COST_DB_PATH", str(billing_db))
    monkeypatch.setenv("AGENTHUB_DELEGATION_DB_PATH", str(delegation_db))
    monkeypatch.setenv("AGENTHUB_MARKETPLACE_DB_PATH", str(marketplace_db))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_DB_PATH", str(procurement_db))
    monkeypatch.delenv("AGENTHUB_ENABLE_UNSAFE_FINANCIAL_MUTATIONS", raising=False)

    billing_service.reset_for_tests(db_path=billing_db)
    cost_storage.reset_for_tests(db_path=billing_db)
    delegation_storage.reset_for_tests(db_path=delegation_db)
    delegation_storage.save_balances(
        {
            "@demo:invoice-summarizer": 1000.0,
            "@demo:support-orchestrator": 1000.0,
        }
    )
    return {
        "billing": billing_db,
        "delegation": delegation_db,
        "marketplace": marketplace_db,
        "procurement": procurement_db,
    }


def _count(db_path: Path, table: str) -> int:
    with sqlite3.connect(db_path) as connection:
        return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def _idempotency_count() -> int:
    from src.idempotency import storage as idempotency_storage

    storage = idempotency_storage._STORAGE
    storage._ensure_ready()
    assert storage._conn is not None
    return int(
        storage._conn.execute("SELECT COUNT(*) FROM idempotency_requests").fetchone()[0]
    )


def _assert_disabled(response) -> None:
    assert response.status_code == 503
    assert response.json() == DISABLED_RESPONSE
    assert response.headers.get("X-AgentHub-Idempotent-Replay") is None


def test_disabled_financial_routes_create_no_domain_or_idempotency_state(
    contained_financial_state: dict[str, Path],
) -> None:
    client = TestClient(app)
    initial_balances = delegation_storage.load_balances()
    requests = [
        (
            "/v1/billing/subscriptions",
            {
                "account_id": "acct-contained",
                "plan_id": "pro-monthly",
                "monthly_fee_usd": 50.0,
                "included_units": 1000,
            },
            "dev-owner-key",
            "s166-billing",
        ),
        (
            "/v1/marketplace/purchase",
            {
                "listing_id": "listing-contained",
                "units": 1,
                "max_total_usd": 1.0,
                "policy_approved": True,
            },
            "partner-owner-key",
            "s166-marketplace",
        ),
        (
            "/v1/procurement/approvals",
            {
                "buyer": "owner-partner",
                "listing_id": "listing-contained",
                "units": 1,
                "estimated_total_usd": 1.0,
            },
            "partner-owner-key",
            "s166-procurement",
        ),
        (
            "/v1/delegations",
            {
                "requester_agent_id": "@demo:support-orchestrator",
                "delegate_agent_id": "@demo:invoice-summarizer",
                "task_spec": {"task": "summarize invoice"},
                "estimated_cost_usd": 0.1,
                "max_budget_usd": 1.0,
                "simulated_actual_cost_usd": 0.1,
            },
            "dev-owner-key",
            "s166-delegation",
        ),
    ]

    for path, payload, api_key, idempotency_key in requests:
        response = client.post(
            path,
            json=payload,
            headers={"X-API-Key": api_key, "Idempotency-Key": idempotency_key},
        )
        _assert_disabled(response)

    assert _idempotency_count() == 0
    assert _count(contained_financial_state["billing"], "billing_subscriptions") == 0
    assert _count(contained_financial_state["billing"], "billing_metering_events") == 0
    assert _count(contained_financial_state["delegation"], "delegation_records") == 0
    assert (
        _count(contained_financial_state["delegation"], "delegation_idempotency") == 0
    )
    assert delegation_storage.load_balances() == initial_balances
    assert not contained_financial_state["marketplace"].exists()
    assert not contained_financial_state["procurement"].exists()


def test_all_financial_transition_shapes_are_blocked_before_lookup(
    contained_financial_state: dict[str, Path],
) -> None:
    client = TestClient(app)
    routes = [
        ("/v1/billing/invoices/missing/reconcile", None),
        ("/v1/billing/invoices/missing/refund", {"amount_usd": 1.0, "reason": "test"}),
        ("/v1/marketplace/contracts/missing/settle", {"units_used": 1}),
        (
            "/v1/marketplace/contracts/missing/disputes",
            {"reason": "test", "requested_amount_usd": 1.0},
        ),
        (
            "/v1/marketplace/disputes/missing/resolve",
            {"resolution": "refund", "approved_amount_usd": 1.0},
        ),
        ("/v1/marketplace/contracts/missing/payout", None),
        (
            "/v1/procurement/policy-packs",
            {
                "buyer": "owner-partner",
                "auto_approve_limit_usd": 1.0,
                "hard_stop_limit_usd": 2.0,
            },
        ),
        (
            "/v1/procurement/approvals/missing/decision",
            {"decision": "approve", "approved_max_total_usd": 1.0},
        ),
        (
            "/v1/procurement/exceptions",
            {
                "buyer": "owner-partner",
                "reason": "test",
                "override_hard_stop_limit_usd": 2.0,
            },
        ),
    ]

    for index, (path, payload) in enumerate(routes):
        response = client.post(
            path,
            json=payload,
            headers={
                "X-API-Key": "platform-owner-key",
                "Idempotency-Key": f"s166-shape-{index}",
            },
        )
        _assert_disabled(response)

    assert _idempotency_count() == 0


def test_auth_reads_and_nonfinancial_marketplace_registry_remain_available(
    contained_financial_state: dict[str, Path],
) -> None:
    client = TestClient(app)
    unauthenticated = client.post(
        "/v1/billing/subscriptions",
        json={
            "account_id": "acct",
            "plan_id": "pro",
            "monthly_fee_usd": 1.0,
            "included_units": 1,
        },
        headers={"Idempotency-Key": "s166-unauthenticated"},
    )
    assert unauthenticated.status_code == 401

    listing = client.post(
        "/v1/marketplace/listings",
        json={
            "capability_ref": "@seed:data-normalizer/normalize-records",
            "unit_price_usd": 0.5,
            "max_units_per_purchase": 10,
            "policy_purchase_limit_usd": 3.0,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s166-listing"},
    )
    assert listing.status_code == 200, listing.text

    listed = client.get(
        "/v1/marketplace/listings", headers={"X-API-Key": "dev-owner-key"}
    )
    assert listed.status_code == 200
    assert [row["listing_id"] for row in listed.json()["data"]] == [
        listing.json()["listing_id"]
    ]

    procurement_read = client.get(
        "/v1/procurement/approvals", headers={"X-API-Key": "dev-owner-key"}
    )
    assert procurement_read.status_code == 200
    assert procurement_read.json() == {"data": []}


def test_explicit_local_opt_in_preserves_existing_development_flows(
    contained_financial_state: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTHUB_ENABLE_UNSAFE_FINANCIAL_MUTATIONS", "true")
    response = TestClient(app).post(
        "/v1/billing/subscriptions",
        json={
            "account_id": "acct-opt-in",
            "plan_id": "pro-monthly",
            "monthly_fee_usd": 50.0,
            "included_units": 1000,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s166-opt-in"},
    )
    assert response.status_code == 200, response.text
    assert _count(contained_financial_state["billing"], "billing_subscriptions") == 1
    assert _idempotency_count() == 1
