from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.common.json_store import read_json_list, write_json_list

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


def load(name: str) -> list[dict[str, Any]]:
    path = _path(name)
    return read_json_list(path)


def save(name: str, rows: list[dict[str, Any]]) -> None:
    path = _path(name)
    write_json_list(path, rows)
