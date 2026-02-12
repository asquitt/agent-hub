from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EVENTS = ROOT / "data" / "cost" / "events.json"


def _path_events() -> Path:
    return Path(os.getenv("AGENTHUB_COST_EVENTS_PATH", str(DEFAULT_EVENTS)))


def _ensure(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("[]\n", encoding="utf-8")


def load_events() -> list[dict[str, Any]]:
    path = _path_events()
    _ensure(path)
    rows = json.loads(path.read_text(encoding="utf-8"))
    return rows if isinstance(rows, list) else []


def save_events(rows: list[dict[str, Any]]) -> None:
    path = _path_events()
    _ensure(path)
    path.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")


def append_event(row: dict[str, Any]) -> None:
    rows = load_events()
    rows.append(row)
    save_events(rows)
