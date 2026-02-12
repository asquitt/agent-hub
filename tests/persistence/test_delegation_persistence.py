from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from src.delegation import storage


def _backup_database(source: Path, target: Path) -> None:
    with sqlite3.connect(str(source)) as src_conn, sqlite3.connect(str(target)) as dst_conn:
        src_conn.backup(dst_conn)


def _restore_database(snapshot: Path, target: Path) -> None:
    with sqlite3.connect(str(snapshot)) as src_conn, sqlite3.connect(str(target)) as dst_conn:
        src_conn.backup(dst_conn)


def test_delegation_storage_migrates_legacy_json_on_first_boot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "delegation.db"
    records_path = tmp_path / "legacy-records.json"
    balances_path = tmp_path / "legacy-balances.json"

    records_path.write_text(
        json.dumps(
            [
                {
                    "delegation_id": "dlg-legacy-1",
                    "requester_agent_id": "@demo:invoice-summarizer",
                    "delegate_agent_id": "@demo:support-orchestrator",
                    "status": "completed",
                    "estimated_cost_usd": 10.0,
                    "actual_cost_usd": 8.0,
                    "created_at": "2026-02-12T00:00:00Z",
                    "updated_at": "2026-02-12T00:00:05Z",
                }
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    balances_path.write_text(
        json.dumps([{"agent_id": "@demo:invoice-summarizer", "balance_usd": 992.0}]) + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("AGENTHUB_DELEGATION_DB_PATH", str(db_path))
    monkeypatch.setenv("AGENTHUB_DELEGATION_RECORDS_PATH", str(records_path))
    monkeypatch.setenv("AGENTHUB_DELEGATION_BALANCES_PATH", str(balances_path))

    storage.reconfigure(db_path=db_path)
    migrated_records = storage.load_records()
    migrated_balances = storage.load_balances()

    assert len(migrated_records) == 1
    assert migrated_records[0]["delegation_id"] == "dlg-legacy-1"
    assert migrated_balances["@demo:invoice-summarizer"] == 992.0

    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM _schema_migrations WHERE scope = 'delegation' AND migration_name = '0001_delegation_foundation.sql'"
        ).fetchone()
        assert row is not None
        assert int(row[0]) == 1


def test_delegation_storage_persists_and_restores_from_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "delegation.db"
    snapshot_path = tmp_path / "delegation-snapshot.db"
    drain_path = tmp_path / "delegation-drain.db"
    empty_records = tmp_path / "empty-records.json"
    empty_balances = tmp_path / "empty-balances.json"

    monkeypatch.setenv("AGENTHUB_DELEGATION_DB_PATH", str(db_path))
    monkeypatch.setenv("AGENTHUB_DELEGATION_RECORDS_PATH", str(empty_records))
    monkeypatch.setenv("AGENTHUB_DELEGATION_BALANCES_PATH", str(empty_balances))

    storage.reset_for_tests(db_path=db_path)
    storage.save_balances({"@demo:invoice-summarizer": 1000.0})
    storage.append_record(
        {
            "delegation_id": "dlg-runtime-1",
            "requester_agent_id": "@demo:invoice-summarizer",
            "delegate_agent_id": "@demo:support-orchestrator",
            "status": "completed",
            "estimated_cost_usd": 5.0,
            "actual_cost_usd": 4.2,
            "created_at": "2026-02-12T00:00:00Z",
            "updated_at": "2026-02-12T00:00:05Z",
        }
    )

    _backup_database(db_path, snapshot_path)

    storage.save_balances({"@demo:invoice-summarizer": 1.0})
    storage.append_record(
        {
            "delegation_id": "dlg-runtime-2",
            "requester_agent_id": "@demo:invoice-summarizer",
            "delegate_agent_id": "@demo:fraud-agent",
            "status": "failed_hard_stop",
            "estimated_cost_usd": 10.0,
            "actual_cost_usd": 12.1,
            "created_at": "2026-02-12T01:00:00Z",
            "updated_at": "2026-02-12T01:00:05Z",
        }
    )

    storage.reconfigure(db_path=drain_path)
    _restore_database(snapshot_path, db_path)
    storage.reconfigure(db_path=db_path)

    balances = storage.load_balances()
    records = storage.load_records()
    record_ids = {row["delegation_id"] for row in records}

    assert balances["@demo:invoice-summarizer"] == 1000.0
    assert record_ids == {"dlg-runtime-1"}
