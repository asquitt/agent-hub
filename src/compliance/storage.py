from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.common.sqlite_collections import append_collection_row, read_collection

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPORTS = ROOT / "data" / "compliance" / "evidence_reports.json"
DEFAULT_DB = ROOT / "data" / "compliance" / "compliance.db"


def _path_reports() -> Path:
    return Path(os.getenv("AGENTHUB_COMPLIANCE_EVIDENCE_PATH", str(DEFAULT_REPORTS)))


def _db_path() -> Path:
    override = os.getenv("AGENTHUB_COMPLIANCE_DB_PATH")
    if override:
        return Path(override)
    if os.getenv("AGENTHUB_COMPLIANCE_EVIDENCE_PATH"):
        return _path_reports().parent / "compliance.db"
    return DEFAULT_DB


def load_reports() -> list[dict[str, Any]]:
    return read_collection(
        db_path=_db_path(),
        scope="compliance",
        collection_name="reports",
        legacy_path=_path_reports(),
    )


def append_report(row: dict[str, Any]) -> None:
    append_collection_row(
        db_path=_db_path(),
        scope="compliance",
        collection_name="reports",
        row=row,
        legacy_path=_path_reports(),
    )
