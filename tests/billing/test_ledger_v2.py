from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from src.billing import service


@pytest.fixture(autouse=True)
def isolate_billing_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    billing_db = tmp_path / "billing.db"
    monkeypatch.setenv("AGENTHUB_BILLING_DB_PATH", str(billing_db))
    monkeypatch.setenv("AGENTHUB_COST_DB_PATH", str(billing_db))
    service.reset_for_tests(db_path=billing_db)
    return billing_db


def _seed_invoice() -> dict:
    service.create_subscription(
        account_id="acct-ledger",
        plan_id="pro-monthly",
        owner="owner-dev",
        monthly_fee_usd=20.0,
        included_units=1000,
    )
    service.record_usage_event(
        account_id="acct-ledger",
        meter="eval_runs",
        quantity=40,
        unit_price_usd=0.05,
        owner="owner-dev",
    )
    return service.generate_invoice(account_id="acct-ledger", owner="owner-dev")


def test_double_entry_integrity_for_invoice_and_refund() -> None:
    invoice = _seed_invoice()
    service.refund_invoice(
        invoice_id=invoice["invoice_id"],
        amount_usd=1.25,
        reason="credit",
        actor="owner-platform",
    )

    check = service.verify_double_entry(source_id=invoice["invoice_id"])
    assert check["valid"] is True
    assert check["transaction_count"] >= 2

    chain = service.verify_ledger_chain()
    assert chain["valid"] is True
    assert chain["entry_count"] >= 4


def test_reconciliation_replay_parity_detects_tampered_invoice(isolate_billing_storage: Path) -> None:
    invoice = _seed_invoice()
    baseline = service.reconcile_invoice(invoice["invoice_id"])
    assert baseline["matched"] is True
    assert baseline["replay_due_usd"] == baseline["expected_due_usd"]

    with sqlite3.connect(str(isolate_billing_storage)) as conn:
        row = conn.execute(
            "SELECT payload_json FROM billing_invoices WHERE invoice_id = ?",
            (invoice["invoice_id"],),
        ).fetchone()
        assert row is not None
        payload = json.loads(str(row[0]))
        payload["subtotal_usd"] = 999.0
        payload["due_usd"] = 999.0
        conn.execute(
            "UPDATE billing_invoices SET payload_json = ? WHERE invoice_id = ?",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")), invoice["invoice_id"]),
        )
        conn.commit()

    tampered = service.reconcile_invoice(invoice["invoice_id"])
    assert tampered["matched"] is False
    assert tampered["replay_due_usd"] != tampered["expected_due_usd"]

    with sqlite3.connect(str(isolate_billing_storage)) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM _schema_migrations WHERE scope = 'billing' AND migration_name = '0001_billing_ledger.sql'"
        ).fetchone()
        assert row is not None
        assert int(row[0]) == 1


def test_ledger_entries_are_immutable(isolate_billing_storage: Path) -> None:
    invoice = _seed_invoice()
    entry_id = service.list_ledger_entries(invoice_id=invoice["invoice_id"])[0]["entry_id"]

    with sqlite3.connect(str(isolate_billing_storage)) as conn:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute(
                "UPDATE billing_ledger_entries SET debit_usd = 999.0 WHERE entry_id = ?",
                (entry_id,),
            )
            conn.commit()

        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM billing_ledger_entries WHERE entry_id = ?", (entry_id,))
            conn.commit()
