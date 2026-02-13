from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.common.json_store import append_json_list_row, read_json_list, write_json_list

ROOT = Path(__file__).resolve().parents[2]
RESULTS_PATH = ROOT / "data" / "evals" / "results.json"


def _current_results_path() -> Path:
    override = os.getenv("AGENTHUB_EVAL_RESULTS_PATH")
    return Path(override) if override else RESULTS_PATH


def load_results() -> list[dict[str, Any]]:
    return read_json_list(_current_results_path())


def save_results(rows: list[dict[str, Any]]) -> None:
    write_json_list(_current_results_path(), rows)


def append_result(result: dict[str, Any]) -> None:
    append_json_list_row(_current_results_path(), result)


def latest_result(agent_id: str, version: str | None = None) -> dict[str, Any] | None:
    rows = load_results()
    candidates = [r for r in rows if r.get("agent_id") == agent_id]
    if version is not None:
        candidates = [r for r in candidates if r.get("version") == version]
    if not candidates:
        return None
    candidates.sort(key=lambda r: r.get("completed_at", ""), reverse=True)
    return candidates[0]
