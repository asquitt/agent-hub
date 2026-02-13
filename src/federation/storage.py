from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.common.sqlite_collections import append_collection_row, read_collection

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_AUDIT = ROOT / "data" / "federation" / "audit.json"
DEFAULT_DB = ROOT / "data" / "federation" / "federation.db"


def _path_audit() -> Path:
    return Path(os.getenv("AGENTHUB_FEDERATION_AUDIT_PATH", str(DEFAULT_AUDIT)))


def _db_path() -> Path:
    override = os.getenv("AGENTHUB_FEDERATION_DB_PATH")
    if override:
        return Path(override)
    if os.getenv("AGENTHUB_FEDERATION_AUDIT_PATH"):
        return _path_audit().parent / "federation.db"
    return DEFAULT_DB


def load_audit() -> list[dict[str, Any]]:
    return read_collection(
        db_path=_db_path(),
        scope="federation",
        collection_name="audit",
        legacy_path=_path_audit(),
    )


def append_audit(row: dict[str, Any]) -> None:
    append_collection_row(
        db_path=_db_path(),
        scope="federation",
        collection_name="audit",
        row=row,
        legacy_path=_path_audit(),
    )
