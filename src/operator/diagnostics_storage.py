from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.common.sqlite_collections import append_collection_row, read_collection, write_collection

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = ROOT / "data" / "operator" / "operator_diagnostics.db"
SCOPE = "operator"
COLLECTION = "startup_diagnostics_snapshots"
MAX_SNAPSHOTS = 500


def _db_path() -> Path:
    raw = os.getenv("AGENTHUB_OPERATOR_DIAGNOSTICS_DB_PATH")
    if raw and raw.strip():
        return Path(raw.strip()).expanduser().resolve()
    return DEFAULT_DB_PATH


def append_snapshot(snapshot: dict[str, Any]) -> None:
    db_path = _db_path()
    append_collection_row(
        db_path=db_path,
        scope=SCOPE,
        collection_name=COLLECTION,
        row=dict(snapshot),
    )
    rows = read_collection(db_path=db_path, scope=SCOPE, collection_name=COLLECTION)
    if len(rows) <= MAX_SNAPSHOTS:
        return
    trimmed = rows[-MAX_SNAPSHOTS:]
    write_collection(db_path=db_path, scope=SCOPE, collection_name=COLLECTION, rows=trimmed)


def list_snapshots(*, limit: int = 20) -> list[dict[str, Any]]:
    rows = read_collection(db_path=_db_path(), scope=SCOPE, collection_name=COLLECTION)
    rows.sort(key=lambda row: str(row.get("captured_at", "")), reverse=True)
    return rows[: max(1, limit)]


def reset_for_tests(*, db_path: Path | None = None) -> None:
    target = db_path.resolve() if db_path is not None else _db_path()
    write_collection(db_path=target, scope=SCOPE, collection_name=COLLECTION, rows=[])
