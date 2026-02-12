from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

from src.persistence import apply_scope_migrations

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "data" / "billing" / "billing.db"


def _path_db() -> Path:
    return Path(os.getenv("AGENTHUB_BILLING_DB_PATH", str(DEFAULT_DB)))


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class BillingStorage:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._state: str | None = None

    def _desired_state(self, db_path: str | Path | None = None) -> str:
        return str(Path(db_path) if db_path is not None else _path_db())

    def _connect(self, db_path: Path) -> sqlite3.Connection:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def _ensure_ready(self) -> None:
        with self._lock:
            desired = self._desired_state()
            if self._conn is not None and desired == self._state:
                return
            self._reconfigure_locked(Path(desired))

    def _reconfigure_locked(self, db_path: Path) -> None:
        if self._conn is not None:
            self._conn.close()
        self._conn = self._connect(db_path)
        apply_scope_migrations(self._conn, "billing")
        self._state = self._desired_state(db_path=db_path)

    def reconfigure(self, db_path: str | Path | None = None) -> None:
        with self._lock:
            self._reconfigure_locked(Path(self._desired_state(db_path=db_path)))

    def reset_for_tests(self, db_path: str | Path | None = None) -> None:
        with self._lock:
            self._reconfigure_locked(Path(self._desired_state(db_path=db_path)))
            assert self._conn is not None
            with self._conn:
                self._conn.execute("DELETE FROM billing_ledger_entries")
                self._conn.execute("DELETE FROM billing_invoices")
                self._conn.execute("DELETE FROM billing_usage_events")
                self._conn.execute("DELETE FROM billing_subscriptions")
                self._conn.execute("DELETE FROM billing_metering_events")

    def upsert_subscription(self, row: dict[str, Any]) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO billing_subscriptions(
                        account_id, plan_id, owner, monthly_fee_usd, included_units, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(account_id) DO UPDATE SET
                        plan_id = excluded.plan_id,
                        owner = excluded.owner,
                        monthly_fee_usd = excluded.monthly_fee_usd,
                        included_units = excluded.included_units,
                        updated_at = excluded.updated_at
                    """,
                    (
                        str(row["account_id"]),
                        str(row["plan_id"]),
                        str(row["owner"]),
                        float(row["monthly_fee_usd"]),
                        int(row["included_units"]),
                        str(row["created_at"]),
                        str(row["updated_at"]),
                    ),
                )

    def get_subscription(self, account_id: str) -> dict[str, Any] | None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                """
                SELECT account_id, plan_id, owner, monthly_fee_usd, included_units, created_at, updated_at
                FROM billing_subscriptions
                WHERE account_id = ?
                """,
                (account_id,),
            ).fetchone()
            if row is None:
                return None
            return {
                "account_id": str(row["account_id"]),
                "plan_id": str(row["plan_id"]),
                "owner": str(row["owner"]),
                "monthly_fee_usd": round(float(row["monthly_fee_usd"]), 6),
                "included_units": int(row["included_units"]),
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
            }

    def insert_usage_event(self, row: dict[str, Any]) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO billing_usage_events(
                        event_id, account_id, owner, meter, quantity, unit_price_usd, cost_usd,
                        timestamp, timestamp_epoch, invoice_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(row["event_id"]),
                        str(row["account_id"]),
                        str(row["owner"]),
                        str(row["meter"]),
                        float(row["quantity"]),
                        float(row["unit_price_usd"]),
                        float(row["cost_usd"]),
                        str(row["timestamp"]),
                        int(row["timestamp_epoch"]),
                        row.get("invoice_id"),
                    ),
                )

    def list_uninvoiced_usage(self, account_id: str) -> list[dict[str, Any]]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(
                """
                SELECT event_id, account_id, owner, meter, quantity, unit_price_usd, cost_usd,
                       timestamp, timestamp_epoch, invoice_id
                FROM billing_usage_events
                WHERE account_id = ? AND invoice_id IS NULL
                ORDER BY timestamp_epoch, event_id
                """,
                (account_id,),
            ).fetchall()
            return [self._usage_row_to_dict(row) for row in rows]

    def list_usage_by_invoice(self, invoice_id: str) -> list[dict[str, Any]]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            rows = self._conn.execute(
                """
                SELECT event_id, account_id, owner, meter, quantity, unit_price_usd, cost_usd,
                       timestamp, timestamp_epoch, invoice_id
                FROM billing_usage_events
                WHERE invoice_id = ?
                ORDER BY timestamp_epoch, event_id
                """,
                (invoice_id,),
            ).fetchall()
            return [self._usage_row_to_dict(row) for row in rows]

    def _usage_row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "event_id": str(row["event_id"]),
            "account_id": str(row["account_id"]),
            "owner": str(row["owner"]),
            "meter": str(row["meter"]),
            "quantity": float(row["quantity"]),
            "unit_price_usd": float(row["unit_price_usd"]),
            "cost_usd": round(float(row["cost_usd"]), 6),
            "timestamp": str(row["timestamp"]),
            "timestamp_epoch": int(row["timestamp_epoch"]),
            "invoice_id": row["invoice_id"],
        }

    def mark_usage_invoiced(self, event_ids: list[str], invoice_id: str) -> None:
        if not event_ids:
            return
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            placeholders = ",".join("?" for _ in event_ids)
            params = [invoice_id, *event_ids]
            with self._conn:
                self._conn.execute(
                    f"UPDATE billing_usage_events SET invoice_id = ? WHERE event_id IN ({placeholders})",
                    tuple(params),
                )

    def insert_invoice(self, row: dict[str, Any]) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            payload = _canonical_json(row)
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO billing_invoices(invoice_id, account_id, owner, created_at, payload_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        str(row["invoice_id"]),
                        str(row["account_id"]),
                        str(row["owner"]),
                        str(row["created_at"]),
                        payload,
                    ),
                )

    def get_invoice(self, invoice_id: str) -> dict[str, Any] | None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                "SELECT payload_json FROM billing_invoices WHERE invoice_id = ?",
                (invoice_id,),
            ).fetchone()
            if row is None:
                return None
            return json.loads(str(row["payload_json"]))

    def update_invoice(self, row: dict[str, Any]) -> None:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            payload = _canonical_json(row)
            with self._conn:
                self._conn.execute(
                    "UPDATE billing_invoices SET payload_json = ? WHERE invoice_id = ?",
                    (payload, str(row["invoice_id"])),
                )

    def _latest_hash(self) -> str:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT entry_hash FROM billing_ledger_entries ORDER BY sequence_id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return "GENESIS"
        return str(row["entry_hash"])

    def append_ledger_transaction(
        self,
        tx_id: str,
        account_id: str,
        source_type: str,
        source_id: str,
        entries: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not entries:
            raise ValueError("ledger transaction must include at least one entry")
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            persisted: list[dict[str, Any]] = []
            prev_hash = self._latest_hash()
            with self._conn:
                for index, entry in enumerate(entries):
                    payload = {
                        "tx_id": tx_id,
                        "account_id": account_id,
                        "source_type": source_type,
                        "source_id": source_id,
                        "entry_order": index,
                        "ledger_account": str(entry["ledger_account"]),
                        "debit_usd": round(float(entry.get("debit_usd", 0.0)), 6),
                        "credit_usd": round(float(entry.get("credit_usd", 0.0)), 6),
                        "currency": str(entry.get("currency", "USD")),
                        "metadata": entry.get("metadata", {}),
                    }
                    encoded = _canonical_json({"prev_hash": prev_hash, **payload})
                    entry_hash = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
                    entry_id = hashlib.sha256(f"{tx_id}:{index}:{entry_hash}".encode("utf-8")).hexdigest()[:24]
                    created_at = str(entry.get("created_at"))
                    if not created_at or created_at == "None":
                        created_at = entry.get("timestamp") or ""
                    if not created_at:
                        created_at = payload["metadata"].get("timestamp", "")
                    if not created_at:
                        created_at = payload["metadata"].get("created_at", "")
                    if not created_at:
                        created_at = str(entry.get("generated_at", ""))
                    if not created_at:
                        created_at = ""
                    self._conn.execute(
                        """
                        INSERT INTO billing_ledger_entries(
                            entry_id, tx_id, entry_order, account_id, source_type, source_id, ledger_account,
                            debit_usd, credit_usd, currency, metadata_json, created_at, prev_hash, entry_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            entry_id,
                            tx_id,
                            index,
                            account_id,
                            source_type,
                            source_id,
                            payload["ledger_account"],
                            payload["debit_usd"],
                            payload["credit_usd"],
                            payload["currency"],
                            _canonical_json(payload["metadata"] if isinstance(payload["metadata"], dict) else {}),
                            created_at,
                            prev_hash,
                            entry_hash,
                        ),
                    )
                    persisted_row = {
                        "entry_id": entry_id,
                        "tx_id": tx_id,
                        "entry_order": index,
                        "account_id": account_id,
                        "source_type": source_type,
                        "source_id": source_id,
                        "ledger_account": payload["ledger_account"],
                        "debit_usd": payload["debit_usd"],
                        "credit_usd": payload["credit_usd"],
                        "currency": payload["currency"],
                        "metadata": payload["metadata"] if isinstance(payload["metadata"], dict) else {},
                        "created_at": created_at,
                        "prev_hash": prev_hash,
                        "entry_hash": entry_hash,
                    }
                    persisted.append(persisted_row)
                    prev_hash = entry_hash
            return persisted

    def list_ledger_entries(
        self,
        tx_id: str | None = None,
        source_type: str | None = None,
        source_id: str | None = None,
    ) -> list[dict[str, Any]]:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            query = """
                SELECT sequence_id, entry_id, tx_id, account_id, source_type, source_id,
                       entry_order, ledger_account, debit_usd, credit_usd, currency, metadata_json,
                       created_at, prev_hash, entry_hash
                FROM billing_ledger_entries
                WHERE 1 = 1
            """
            params: list[str] = []
            if tx_id is not None:
                query += " AND tx_id = ?"
                params.append(tx_id)
            if source_type is not None:
                query += " AND source_type = ?"
                params.append(source_type)
            if source_id is not None:
                query += " AND source_id = ?"
                params.append(source_id)
            query += " ORDER BY sequence_id"
            rows = self._conn.execute(query, tuple(params)).fetchall()
            return [
                {
                    "sequence_id": int(row["sequence_id"]),
                    "entry_id": str(row["entry_id"]),
                    "tx_id": str(row["tx_id"]),
                    "entry_order": int(row["entry_order"]),
                    "account_id": str(row["account_id"]),
                    "source_type": str(row["source_type"]),
                    "source_id": str(row["source_id"]),
                    "ledger_account": str(row["ledger_account"]),
                    "debit_usd": round(float(row["debit_usd"]), 6),
                    "credit_usd": round(float(row["credit_usd"]), 6),
                    "currency": str(row["currency"]),
                    "metadata": json.loads(str(row["metadata_json"])),
                    "created_at": str(row["created_at"]),
                    "prev_hash": str(row["prev_hash"]),
                    "entry_hash": str(row["entry_hash"]),
                }
                for row in rows
            ]

    def verify_ledger_chain(self) -> dict[str, Any]:
        rows = self.list_ledger_entries()
        expected_prev = "GENESIS"
        broken_at: int | None = None
        for row in rows:
            if row["prev_hash"] != expected_prev:
                broken_at = row["sequence_id"]
                break
            payload = {
                "prev_hash": row["prev_hash"],
                "tx_id": row["tx_id"],
                "account_id": row["account_id"],
                "source_type": row["source_type"],
                "source_id": row["source_id"],
                "entry_order": row["entry_order"],
                "ledger_account": row["ledger_account"],
                "debit_usd": row["debit_usd"],
                "credit_usd": row["credit_usd"],
                "currency": row["currency"],
                "metadata": row["metadata"],
            }
            recomputed = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
            if recomputed != row["entry_hash"]:
                broken_at = row["sequence_id"]
                break
            expected_prev = row["entry_hash"]
        return {"valid": broken_at is None, "entry_count": len(rows), "broken_at_sequence": broken_at}

    def invoice_usage_sum(self, invoice_id: str) -> float:
        self._ensure_ready()
        with self._lock:
            assert self._conn is not None
            row = self._conn.execute(
                "SELECT COALESCE(SUM(cost_usd), 0.0) AS total FROM billing_usage_events WHERE invoice_id = ?",
                (invoice_id,),
            ).fetchone()
            return round(float(row["total"]), 6) if row is not None else 0.0


_STORAGE = BillingStorage()


def reset_for_tests(db_path: str | Path | None = None) -> None:
    _STORAGE.reset_for_tests(db_path=db_path)


def reconfigure(db_path: str | Path | None = None) -> None:
    _STORAGE.reconfigure(db_path=db_path)


def upsert_subscription(row: dict[str, Any]) -> None:
    _STORAGE.upsert_subscription(row)


def get_subscription(account_id: str) -> dict[str, Any] | None:
    return _STORAGE.get_subscription(account_id)


def insert_usage_event(row: dict[str, Any]) -> None:
    _STORAGE.insert_usage_event(row)


def list_uninvoiced_usage(account_id: str) -> list[dict[str, Any]]:
    return _STORAGE.list_uninvoiced_usage(account_id)


def list_usage_by_invoice(invoice_id: str) -> list[dict[str, Any]]:
    return _STORAGE.list_usage_by_invoice(invoice_id)


def mark_usage_invoiced(event_ids: list[str], invoice_id: str) -> None:
    _STORAGE.mark_usage_invoiced(event_ids=event_ids, invoice_id=invoice_id)


def insert_invoice(row: dict[str, Any]) -> None:
    _STORAGE.insert_invoice(row)


def get_invoice(invoice_id: str) -> dict[str, Any] | None:
    return _STORAGE.get_invoice(invoice_id)


def update_invoice(row: dict[str, Any]) -> None:
    _STORAGE.update_invoice(row)


def append_ledger_transaction(
    tx_id: str,
    account_id: str,
    source_type: str,
    source_id: str,
    entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return _STORAGE.append_ledger_transaction(
        tx_id=tx_id,
        account_id=account_id,
        source_type=source_type,
        source_id=source_id,
        entries=entries,
    )


def list_ledger_entries(
    tx_id: str | None = None,
    source_type: str | None = None,
    source_id: str | None = None,
) -> list[dict[str, Any]]:
    return _STORAGE.list_ledger_entries(tx_id=tx_id, source_type=source_type, source_id=source_id)


def verify_ledger_chain() -> dict[str, Any]:
    return _STORAGE.verify_ledger_chain()


def invoice_usage_sum(invoice_id: str) -> float:
    return _STORAGE.invoice_usage_sum(invoice_id)
