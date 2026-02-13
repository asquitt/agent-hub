from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.common.json_store import append_json_list_row, read_json_list

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPORTS = ROOT / "data" / "compliance" / "evidence_reports.json"


def _path_reports() -> Path:
    return Path(os.getenv("AGENTHUB_COMPLIANCE_EVIDENCE_PATH", str(DEFAULT_REPORTS)))


def load_reports() -> list[dict[str, Any]]:
    return read_json_list(_path_reports())


def append_report(row: dict[str, Any]) -> None:
    append_json_list_row(_path_reports(), row)
