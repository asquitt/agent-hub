from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.common.sqlite_collections import read_collection, write_collection

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "data" / "knowledge" / "knowledge.db"


def _db_path() -> Path:
    override = os.getenv("AGENTHUB_KNOWLEDGE_DB_PATH")
    if override:
        return Path(override)
    return DEFAULT_DB


def load_entries() -> dict[str, dict[str, Any]]:
    rows = read_collection(db_path=_db_path(), scope="knowledge", collection_name="entries")
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        entry_id = str(row.get("entry_id", "")).strip()
        if entry_id:
            out[entry_id] = row
    return out


def save_entries(rows: dict[str, dict[str, Any]]) -> None:
    write_collection(
        db_path=_db_path(),
        scope="knowledge",
        collection_name="entries",
        rows=list(rows.values()),
    )


def reset_for_tests(db_path: str | Path | None = None) -> None:
    if db_path is not None:
        os.environ["AGENTHUB_KNOWLEDGE_DB_PATH"] = str(Path(db_path))
    save_entries({})
