from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_AUDIT = ROOT / "data" / "federation" / "audit.json"


def _path_audit() -> Path:
    return Path(os.getenv("AGENTHUB_FEDERATION_AUDIT_PATH", str(DEFAULT_AUDIT)))


def _ensure(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("[]\n", encoding="utf-8")


def load_audit() -> list[dict[str, Any]]:
    path = _path_audit()
    _ensure(path)
    rows = json.loads(path.read_text(encoding="utf-8"))
    return rows if isinstance(rows, list) else []


def append_audit(row: dict[str, Any]) -> None:
    rows = load_audit()
    rows.append(row)
    path = _path_audit()
    _ensure(path)
    path.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
