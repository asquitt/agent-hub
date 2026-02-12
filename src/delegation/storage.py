from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RECORDS = ROOT / "data" / "delegations" / "records.json"
DEFAULT_BALANCES = ROOT / "data" / "delegations" / "balances.json"


def _path_records() -> Path:
    return Path(os.getenv("AGENTHUB_DELEGATION_RECORDS_PATH", str(DEFAULT_RECORDS)))


def _path_balances() -> Path:
    return Path(os.getenv("AGENTHUB_DELEGATION_BALANCES_PATH", str(DEFAULT_BALANCES)))


def _ensure(path: Path, default: str = "[]\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(default, encoding="utf-8")


def load_records() -> list[dict[str, Any]]:
    path = _path_records()
    _ensure(path)
    rows = json.loads(path.read_text(encoding="utf-8"))
    return rows if isinstance(rows, list) else []


def save_records(rows: list[dict[str, Any]]) -> None:
    path = _path_records()
    _ensure(path)
    path.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")


def append_record(row: dict[str, Any]) -> None:
    rows = load_records()
    rows.append(row)
    save_records(rows)


def get_record(delegation_id: str) -> dict[str, Any] | None:
    for row in load_records():
        if row.get("delegation_id") == delegation_id:
            return row
    return None


def load_balances() -> dict[str, float]:
    path = _path_balances()
    _ensure(path)
    rows = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, float] = {}
    if isinstance(rows, list):
        for row in rows:
            out[str(row.get("agent_id"))] = float(row.get("balance_usd", 0.0))
    return out


def save_balances(balances: dict[str, float]) -> None:
    path = _path_balances()
    _ensure(path)
    rows = [{"agent_id": key, "balance_usd": round(value, 6)} for key, value in sorted(balances.items())]
    path.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
