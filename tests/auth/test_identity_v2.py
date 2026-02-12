from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.billing import service as billing_service


@pytest.fixture(autouse=True)
def isolate_identity_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    billing_db = tmp_path / "billing.db"
    monkeypatch.setenv("AGENTHUB_AUTH_TOKEN_SECRET", "test-secret-s32")
    monkeypatch.setenv("AGENTHUB_BILLING_DB_PATH", str(billing_db))
    monkeypatch.setenv("AGENTHUB_COST_DB_PATH", str(billing_db))
    billing_service.reset_for_tests(db_path=billing_db)


def _issue_token(client: TestClient, api_key: str, scopes: list[str]) -> str:
    response = client.post(
        "/v1/auth/tokens",
        json={"scopes": scopes, "ttl_seconds": 1200},
        headers={"X-API-Key": api_key},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _seed_invoice(client: TestClient) -> str:
    create_subscription = client.post(
        "/v1/billing/subscriptions",
        json={
            "account_id": "acct-s32",
            "plan_id": "pro-monthly",
            "monthly_fee_usd": 20.0,
            "included_units": 500,
        },
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert create_subscription.status_code == 200

    usage = client.post(
        "/v1/billing/usage",
        json={
            "account_id": "acct-s32",
            "meter": "delegation_calls",
            "quantity": 100,
            "unit_price_usd": 0.02,
        },
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert usage.status_code == 200

    invoice = client.post(
        "/v1/billing/invoices/generate",
        json={"account_id": "acct-s32"},
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert invoice.status_code == 200, invoice.text
    return invoice.json()["invoice_id"]


def test_operator_refresh_requires_scope_for_bearer_tokens() -> None:
    client = TestClient(app)
    allowed_token = _issue_token(client, api_key="dev-owner-key", scopes=["operator.refresh"])
    blocked_token = _issue_token(client, api_key="dev-owner-key", scopes=["billing.refund"])

    allowed = client.post(
        "/v1/operator/refresh",
        headers={"Authorization": f"Bearer {allowed_token}", "X-Operator-Role": "admin"},
    )
    assert allowed.status_code == 200, allowed.text

    blocked = client.post(
        "/v1/operator/refresh",
        headers={"Authorization": f"Bearer {blocked_token}", "X-Operator-Role": "admin"},
    )
    assert blocked.status_code == 403


def test_billing_refund_scope_matrix_for_bearer_tokens() -> None:
    client = TestClient(app)
    invoice_id = _seed_invoice(client)

    missing_scope = _issue_token(client, api_key="platform-owner-key", scopes=["operator.refresh"])
    with_scope = _issue_token(client, api_key="platform-owner-key", scopes=["billing.refund"])

    denied = client.post(
        f"/v1/billing/invoices/{invoice_id}/refund",
        json={"amount_usd": 1.0, "reason": "scope-check"},
        headers={"Authorization": f"Bearer {missing_scope}"},
    )
    assert denied.status_code == 403

    allowed = client.post(
        f"/v1/billing/invoices/{invoice_id}/refund",
        json={"amount_usd": 1.0, "reason": "scope-check"},
        headers={"Authorization": f"Bearer {with_scope}"},
    )
    assert allowed.status_code == 200, allowed.text
