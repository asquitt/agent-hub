from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.common.sqlite_collections import read_collection, write_collection

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = ROOT / "data" / "lease" / "lease.db"


def _db_path() -> Path:
    override = os.getenv("AGENTHUB_LEASE_DB_PATH")
    if override:
        return Path(override)
    return DEFAULT_DB


def _load_map(collection_name: str, id_key: str) -> dict[str, dict[str, Any]]:
    rows = read_collection(db_path=_db_path(), scope="lease", collection_name=collection_name)
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        row_id = str(row.get(id_key, "")).strip()
        if row_id:
            out[row_id] = row
    return out


def _save_map(collection_name: str, rows: dict[str, dict[str, Any]]) -> None:
    write_collection(
        db_path=_db_path(),
        scope="lease",
        collection_name=collection_name,
        rows=list(rows.values()),
    )


def load_leases() -> dict[str, dict[str, Any]]:
    return _load_map(collection_name="leases", id_key="lease_id")


def save_leases(rows: dict[str, dict[str, Any]]) -> None:
    _save_map(collection_name="leases", rows=rows)


def load_installs() -> dict[str, dict[str, Any]]:
    return _load_map(collection_name="installs", id_key="install_id")


def save_installs(rows: dict[str, dict[str, Any]]) -> None:
    _save_map(collection_name="installs", rows=rows)


def reset_for_tests(db_path: str | Path | None = None) -> None:
    if db_path is not None:
        os.environ["AGENTHUB_LEASE_DB_PATH"] = str(Path(db_path))
    save_leases({})
    save_installs({})
