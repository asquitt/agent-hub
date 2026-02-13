from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.common.json_store import append_json_list_row, read_json_list

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_AUDIT = ROOT / "data" / "federation" / "audit.json"


def _path_audit() -> Path:
    return Path(os.getenv("AGENTHUB_FEDERATION_AUDIT_PATH", str(DEFAULT_AUDIT)))


def load_audit() -> list[dict[str, Any]]:
    return read_json_list(_path_audit())


def append_audit(row: dict[str, Any]) -> None:
    append_json_list_row(_path_audit(), row)
