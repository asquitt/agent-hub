from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.common.sqlite_collections import append_collection_row, read_collection, write_collection

ROOT = Path(__file__).resolve().parents[2]
RESULTS_PATH = ROOT / "data" / "evals" / "results.json"
DEFAULT_DB = ROOT / "data" / "evals" / "evals.db"


def _current_results_path() -> Path:
    override = os.getenv("AGENTHUB_EVAL_RESULTS_PATH")
    return Path(override) if override else RESULTS_PATH


def _db_path() -> Path:
    override = os.getenv("AGENTHUB_EVAL_DB_PATH")
    if override:
        return Path(override)
    if os.getenv("AGENTHUB_EVAL_RESULTS_PATH"):
        return _current_results_path().parent / "evals.db"
    return DEFAULT_DB


def load_results() -> list[dict[str, Any]]:
    return read_collection(
        db_path=_db_path(),
        scope="eval",
        collection_name="results",
        legacy_path=_current_results_path(),
    )


def save_results(rows: list[dict[str, Any]]) -> None:
    write_collection(
        db_path=_db_path(),
        scope="eval",
        collection_name="results",
        rows=rows,
    )


def append_result(result: dict[str, Any]) -> None:
    append_collection_row(
        db_path=_db_path(),
        scope="eval",
        collection_name="results",
        row=result,
        legacy_path=_current_results_path(),
    )


def latest_result(agent_id: str, version: str | None = None) -> dict[str, Any] | None:
    rows = load_results()
    candidates = [r for r in rows if r.get("agent_id") == agent_id]
    if version is not None:
        candidates = [r for r in candidates if r.get("version") == version]
    if not candidates:
        return None
    candidates.sort(key=lambda r: r.get("completed_at", ""), reverse=True)
    return candidates[0]
