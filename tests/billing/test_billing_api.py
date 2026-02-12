from __future__ import annotations

from fastapi.testclient import TestClient

from src.api.app import app
from src.billing import service


def _seed_invoice(client: TestClient) -> dict:
    create_subscription = client.post(
        "/v1/billing/subscriptions",
        json={
            "account_id": "acct-alpha",
            "plan_id": "pro-monthly",
            "monthly_fee_usd": 50.0,
            "included_units": 1000,
        },
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert create_subscription.status_code == 200

    usage_1 = client.post(
        "/v1/billing/usage",
        json={
            "account_id": "acct-alpha",
            "meter": "delegation_calls",
            "quantity": 100,
            "unit_price_usd": 0.02,
        },
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert usage_1.status_code == 200

    usage_2 = client.post(
        "/v1/billing/usage",
        json={
            "account_id": "acct-alpha",
            "meter": "eval_runs",
            "quantity": 50,
            "unit_price_usd": 0.05,
        },
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert usage_2.status_code == 200

    invoice = client.post(
        "/v1/billing/invoices/generate",
        json={"account_id": "acct-alpha"},
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert invoice.status_code == 200, invoice.text
    return invoice.json()


def test_billing_metering_accuracy_and_reconciliation() -> None:
    service.SUBSCRIPTIONS.clear()
    service.USAGE_EVENTS.clear()
    service.INVOICES.clear()

    client = TestClient(app)
    invoice = _seed_invoice(client)

    # 50.0 subscription + (100*0.02 + 50*0.05) usage = 54.5
    assert invoice["subtotal_usd"] == 54.5
    assert invoice["due_usd"] == 54.5

    reconcile = client.post(
        f"/v1/billing/invoices/{invoice['invoice_id']}/reconcile",
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert reconcile.status_code == 200, reconcile.text
    payload = reconcile.json()
    assert payload["matched"] is True
    assert payload["delta_usd"] == 0


def test_billing_refund_admin_flow() -> None:
    service.SUBSCRIPTIONS.clear()
    service.USAGE_EVENTS.clear()
    service.INVOICES.clear()

    client = TestClient(app)
    invoice = _seed_invoice(client)

    non_admin = client.post(
        f"/v1/billing/invoices/{invoice['invoice_id']}/refund",
        json={"amount_usd": 4.5, "reason": "service outage credit"},
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert non_admin.status_code == 403

    admin = client.post(
        f"/v1/billing/invoices/{invoice['invoice_id']}/refund",
        json={"amount_usd": 4.5, "reason": "service outage credit"},
        headers={"X-API-Key": "platform-owner-key"},
    )
    assert admin.status_code == 200, admin.text
    refunded = admin.json()
    assert refunded["refunded_usd"] == 4.5
    assert refunded["due_usd"] == 50.0

    over_refund = client.post(
        f"/v1/billing/invoices/{invoice['invoice_id']}/refund",
        json={"amount_usd": 999, "reason": "invalid"},
        headers={"X-API-Key": "platform-owner-key"},
    )
    assert over_refund.status_code == 400
