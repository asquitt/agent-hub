from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.cost_governance import storage as cost_storage


@pytest.fixture(autouse=True)
def isolate_marketplace_and_procurement_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    billing_db = tmp_path / "billing.db"
    monkeypatch.setenv("AGENTHUB_MARKETPLACE_LISTINGS_PATH", str(tmp_path / "listings.json"))
    monkeypatch.setenv("AGENTHUB_MARKETPLACE_CONTRACTS_PATH", str(tmp_path / "contracts.json"))
    monkeypatch.setenv("AGENTHUB_MARKETPLACE_DISPUTES_PATH", str(tmp_path / "disputes.json"))
    monkeypatch.setenv("AGENTHUB_MARKETPLACE_PAYOUTS_PATH", str(tmp_path / "payouts.json"))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_POLICY_PACKS_PATH", str(tmp_path / "proc-policy-packs.json"))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_APPROVALS_PATH", str(tmp_path / "proc-approvals.json"))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_EXCEPTIONS_PATH", str(tmp_path / "proc-exceptions.json"))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_AUDIT_PATH", str(tmp_path / "proc-audit.json"))
    monkeypatch.setenv("AGENTHUB_COST_EVENTS_PATH", str(tmp_path / "cost-events.json"))
    monkeypatch.setenv("AGENTHUB_COST_DB_PATH", str(billing_db))
    monkeypatch.setenv("AGENTHUB_BILLING_DB_PATH", str(billing_db))
    cost_storage.reset_for_tests(db_path=billing_db)


def _headers(api_key: str, idempotency_key: str) -> dict[str, str]:
    return {"X-API-Key": api_key, "Idempotency-Key": idempotency_key}


def _create_listing(client: TestClient, *, unit_price_usd: float = 1.0) -> str:
    response = client.post(
        "/v1/marketplace/listings",
        json={
            "capability_ref": "@seed:data-normalizer/normalize-records",
            "unit_price_usd": unit_price_usd,
            "max_units_per_purchase": 10,
            "policy_purchase_limit_usd": 10.0,
        },
        headers=_headers("dev-owner-key", f"s60-proc-listing-{unit_price_usd}"),
    )
    assert response.status_code == 200, response.text
    return response.json()["listing_id"]


def test_procurement_policy_boundary_requires_approval_and_admin_decision() -> None:
    client = TestClient(app)
    listing_id = _create_listing(client)

    pack = client.post(
        "/v1/procurement/policy-packs",
        json={
            "buyer": "owner-partner",
            "auto_approve_limit_usd": 1.0,
            "hard_stop_limit_usd": 5.0,
            "allowed_sellers": ["owner-dev"],
        },
        headers=_headers("platform-owner-key", "s60-proc-pack-1"),
    )
    assert pack.status_code == 200, pack.text

    denied_without_approval = client.post(
        "/v1/marketplace/purchase",
        json={
            "listing_id": listing_id,
            "units": 3,
            "max_total_usd": 10.0,
            "policy_approved": True,
        },
        headers=_headers("partner-owner-key", "s60-proc-purchase-deny-1"),
    )
    assert denied_without_approval.status_code == 403
    assert "approval required" in denied_without_approval.json()["detail"]

    approval_request = client.post(
        "/v1/procurement/approvals",
        json={
            "buyer": "owner-partner",
            "listing_id": listing_id,
            "units": 3,
            "estimated_total_usd": 3.0,
            "note": "procurement review needed",
        },
        headers=_headers("partner-owner-key", "s60-proc-approval-request-1"),
    )
    assert approval_request.status_code == 200, approval_request.text
    approval_id = approval_request.json()["approval_id"]

    denied_decision = client.post(
        f"/v1/procurement/approvals/{approval_id}/decision",
        json={"decision": "approve"},
        headers=_headers("partner-owner-key", "s60-proc-approval-decision-deny-1"),
    )
    assert denied_decision.status_code == 403

    approve = client.post(
        f"/v1/procurement/approvals/{approval_id}/decision",
        json={"decision": "approve", "approved_max_total_usd": 3.0, "note": "approved"},
        headers=_headers("platform-owner-key", "s60-proc-approval-decision-1"),
    )
    assert approve.status_code == 200, approve.text
    assert approve.json()["status"] == "approved"

    purchase = client.post(
        "/v1/marketplace/purchase",
        json={
            "listing_id": listing_id,
            "units": 3,
            "max_total_usd": 10.0,
            "policy_approved": True,
            "procurement_approval_id": approval_id,
        },
        headers=_headers("partner-owner-key", "s60-proc-purchase-allow-1"),
    )
    assert purchase.status_code == 200, purchase.text
    procurement = purchase.json()["procurement_decision"]
    assert procurement["approval_id"] == approval_id
    assert procurement["policy_pack_id"] == pack.json()["pack_id"]


def test_procurement_hard_stop_requires_exception_path() -> None:
    client = TestClient(app)
    listing_id = _create_listing(client)

    pack = client.post(
        "/v1/procurement/policy-packs",
        json={
            "buyer": "owner-partner",
            "auto_approve_limit_usd": 1.0,
            "hard_stop_limit_usd": 2.0,
            "allowed_sellers": ["owner-dev"],
        },
        headers=_headers("platform-owner-key", "s60-proc-pack-2"),
    )
    assert pack.status_code == 200

    approval_request = client.post(
        "/v1/procurement/approvals",
        json={
            "buyer": "owner-partner",
            "listing_id": listing_id,
            "units": 3,
            "estimated_total_usd": 3.0,
        },
        headers=_headers("partner-owner-key", "s60-proc-approval-request-2"),
    )
    approval_id = approval_request.json()["approval_id"]
    approve = client.post(
        f"/v1/procurement/approvals/{approval_id}/decision",
        json={"decision": "approve", "approved_max_total_usd": 4.0},
        headers=_headers("platform-owner-key", "s60-proc-approval-decision-2"),
    )
    assert approve.status_code == 200

    denied_without_exception = client.post(
        "/v1/marketplace/purchase",
        json={
            "listing_id": listing_id,
            "units": 3,
            "max_total_usd": 10.0,
            "policy_approved": True,
            "procurement_approval_id": approval_id,
        },
        headers=_headers("partner-owner-key", "s60-proc-purchase-deny-2"),
    )
    assert denied_without_exception.status_code == 403
    assert "hard stop limit" in denied_without_exception.json()["detail"]

    denied_exception_create = client.post(
        "/v1/procurement/exceptions",
        json={
            "buyer": "owner-partner",
            "reason": "temporary budget extension",
            "override_hard_stop_limit_usd": 3.5,
        },
        headers=_headers("partner-owner-key", "s60-proc-exception-deny-2"),
    )
    assert denied_exception_create.status_code == 403

    exception = client.post(
        "/v1/procurement/exceptions",
        json={
            "buyer": "owner-partner",
            "reason": "temporary budget extension",
            "override_hard_stop_limit_usd": 3.5,
        },
        headers=_headers("platform-owner-key", "s60-proc-exception-create-2"),
    )
    assert exception.status_code == 200, exception.text
    exception_id = exception.json()["exception_id"]

    purchase = client.post(
        "/v1/marketplace/purchase",
        json={
            "listing_id": listing_id,
            "units": 3,
            "max_total_usd": 10.0,
            "policy_approved": True,
            "procurement_approval_id": approval_id,
            "procurement_exception_id": exception_id,
        },
        headers=_headers("partner-owner-key", "s60-proc-purchase-allow-2"),
    )
    assert purchase.status_code == 200, purchase.text
    procurement = purchase.json()["procurement_decision"]
    assert procurement["exception_id"] == exception_id
    assert "procurement.exception_applied" in procurement["reason_codes"]


def test_procurement_audit_visibility_and_scope_boundaries() -> None:
    client = TestClient(app)
    listing_id = _create_listing(client, unit_price_usd=0.8)

    pack = client.post(
        "/v1/procurement/policy-packs",
        json={
            "buyer": "owner-partner",
            "auto_approve_limit_usd": 1.0,
            "hard_stop_limit_usd": 4.0,
            "allowed_sellers": ["owner-dev"],
        },
        headers=_headers("platform-owner-key", "s60-proc-pack-3"),
    )
    assert pack.status_code == 200

    purchase = client.post(
        "/v1/marketplace/purchase",
        json={
            "listing_id": listing_id,
            "units": 1,
            "max_total_usd": 2.0,
            "policy_approved": True,
        },
        headers=_headers("partner-owner-key", "s60-proc-purchase-allow-3"),
    )
    assert purchase.status_code == 200

    audit = client.get(
        "/v1/procurement/audit",
        params={"buyer": "owner-partner", "limit": 50},
        headers={"X-API-Key": "platform-owner-key"},
    )
    assert audit.status_code == 200
    actions = {row["action"] for row in audit.json()["data"]}
    assert "policy_pack.upsert" in actions
    assert "purchase.evaluate" in actions

    denied_cross_scope = client.get(
        "/v1/procurement/audit",
        params={"buyer": "owner-dev"},
        headers={"X-API-Key": "partner-owner-key"},
    )
    assert denied_cross_scope.status_code == 403
