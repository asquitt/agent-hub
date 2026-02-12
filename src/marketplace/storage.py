from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LISTINGS = ROOT / "data" / "marketplace" / "listings.json"
DEFAULT_CONTRACTS = ROOT / "data" / "marketplace" / "contracts.json"
DEFAULT_DISPUTES = ROOT / "data" / "marketplace" / "disputes.json"
DEFAULT_PAYOUTS = ROOT / "data" / "marketplace" / "payouts.json"


def _path(name: str) -> Path:
    if name == "listings":
        return Path(os.getenv("AGENTHUB_MARKETPLACE_LISTINGS_PATH", str(DEFAULT_LISTINGS)))
    if name == "contracts":
        return Path(os.getenv("AGENTHUB_MARKETPLACE_CONTRACTS_PATH", str(DEFAULT_CONTRACTS)))
    if name == "disputes":
        return Path(os.getenv("AGENTHUB_MARKETPLACE_DISPUTES_PATH", str(DEFAULT_DISPUTES)))
    if name == "payouts":
        return Path(os.getenv("AGENTHUB_MARKETPLACE_PAYOUTS_PATH", str(DEFAULT_PAYOUTS)))
    raise ValueError(f"unsupported marketplace storage name: {name}")


def _ensure(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("[]\n", encoding="utf-8")


def load(name: str) -> list[dict[str, Any]]:
    path = _path(name)
    _ensure(path)
    rows = json.loads(path.read_text(encoding="utf-8"))
    return rows if isinstance(rows, list) else []


def save(name: str, rows: list[dict[str, Any]]) -> None:
    path = _path(name)
    _ensure(path)
    path.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
