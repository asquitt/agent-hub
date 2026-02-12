from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPORTS = ROOT / "data" / "compliance" / "evidence_reports.json"


def _path_reports() -> Path:
    return Path(os.getenv("AGENTHUB_COMPLIANCE_EVIDENCE_PATH", str(DEFAULT_REPORTS)))


def _ensure(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("[]\n", encoding="utf-8")


def load_reports() -> list[dict[str, Any]]:
    path = _path_reports()
    _ensure(path)
    rows = json.loads(path.read_text(encoding="utf-8"))
    return rows if isinstance(rows, list) else []


def append_report(row: dict[str, Any]) -> None:
    rows = load_reports()
    rows.append(row)
    path = _path_reports()
    _ensure(path)
    path.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
