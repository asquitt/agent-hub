from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.billing import service


@pytest.fixture(autouse=True)
def isolate_billing_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    billing_db = tmp_path / "billing.db"
    monkeypatch.setenv("AGENTHUB_BILLING_DB_PATH", str(billing_db))
    monkeypatch.setenv("AGENTHUB_COST_DB_PATH", str(billing_db))
    service.reset_for_tests(db_path=billing_db)


def _seed_invoice(client: TestClient) -> dict:
    create_subscription = client.post(
        "/v1/billing/subscriptions",
        json={
            "account_id": "acct-alpha",
            "plan_id": "pro-monthly",
            "monthly_fee_usd": 50.0,
            "included_units": 1000,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s39-subscription"},
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
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s39-usage-1"},
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
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s39-usage-2"},
    )
    assert usage_2.status_code == 200

    invoice = client.post(
        "/v1/billing/invoices/generate",
        json={"account_id": "acct-alpha"},
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s39-generate"},
    )
    assert invoice.status_code == 200, invoice.text
    return invoice.json()


def test_billing_metering_accuracy_and_reconciliation() -> None:
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
    assert payload["double_entry_balanced"] is True
    assert payload["replay_due_usd"] == invoice["due_usd"]
    assert payload["chain_valid"] is True


def test_billing_refund_admin_flow() -> None:
    client = TestClient(app)
    invoice = _seed_invoice(client)

    non_admin = client.post(
        f"/v1/billing/invoices/{invoice['invoice_id']}/refund",
        json={"amount_usd": 4.5, "reason": "service outage credit"},
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s39-refund-non-admin"},
    )
    assert non_admin.status_code == 403

    admin = client.post(
        f"/v1/billing/invoices/{invoice['invoice_id']}/refund",
        json={"amount_usd": 4.5, "reason": "service outage credit"},
        headers={"X-API-Key": "platform-owner-key", "Idempotency-Key": "s39-refund-admin"},
    )
    assert admin.status_code == 200, admin.text
    refunded = admin.json()
    assert refunded["refunded_usd"] == 4.5
    assert refunded["due_usd"] == 50.0

    over_refund = client.post(
        f"/v1/billing/invoices/{invoice['invoice_id']}/refund",
        json={"amount_usd": 999, "reason": "invalid"},
        headers={"X-API-Key": "platform-owner-key", "Idempotency-Key": "s39-refund-over"},
    )
    assert over_refund.status_code == 400


def test_billing_double_entry_and_replay_parity() -> None:
    client = TestClient(app)
    invoice = _seed_invoice(client)
    invoice_id = str(invoice["invoice_id"])

    ledger = service.list_ledger_entries(invoice_id=invoice_id)
    assert ledger, "invoice issuance must emit ledger entries"

    double_entry = service.verify_double_entry(source_id=invoice_id)
    assert double_entry["valid"] is True
    assert double_entry["transaction_count"] >= 1

    first_replay = service.replay_invoice_accounts(invoice_id)
    second_replay = service.replay_invoice_accounts(invoice_id)
    assert first_replay == second_replay
    assert first_replay["accounts_receivable"] == invoice["due_usd"]

    chain = service.verify_ledger_chain()
    assert chain["valid"] is True
