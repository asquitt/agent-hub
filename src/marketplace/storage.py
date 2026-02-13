from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.common.sqlite_collections import read_collection, write_collection

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LISTINGS = ROOT / "data" / "marketplace" / "listings.json"
DEFAULT_CONTRACTS = ROOT / "data" / "marketplace" / "contracts.json"
DEFAULT_DISPUTES = ROOT / "data" / "marketplace" / "disputes.json"
DEFAULT_PAYOUTS = ROOT / "data" / "marketplace" / "payouts.json"
DEFAULT_DB = ROOT / "data" / "marketplace" / "marketplace.db"


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


def _db_path() -> Path:
    override = os.getenv("AGENTHUB_MARKETPLACE_DB_PATH")
    if override:
        return Path(override)
    for legacy_env in (
        "AGENTHUB_MARKETPLACE_LISTINGS_PATH",
        "AGENTHUB_MARKETPLACE_CONTRACTS_PATH",
        "AGENTHUB_MARKETPLACE_DISPUTES_PATH",
        "AGENTHUB_MARKETPLACE_PAYOUTS_PATH",
    ):
        if os.getenv(legacy_env):
            return _path("listings").parent / "marketplace.db"
    return DEFAULT_DB


def load(name: str) -> list[dict[str, Any]]:
    return read_collection(
        db_path=_db_path(),
        scope="marketplace",
        collection_name=name,
        legacy_path=_path(name),
    )


def save(name: str, rows: list[dict[str, Any]]) -> None:
    write_collection(
        db_path=_db_path(),
        scope="marketplace",
        collection_name=name,
        rows=rows,
    )
