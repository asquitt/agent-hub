from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
RESULTS_PATH = ROOT / "data" / "evals" / "results.json"


def _current_results_path() -> Path:
    override = os.getenv("AGENTHUB_EVAL_RESULTS_PATH")
    return Path(override) if override else RESULTS_PATH


def _ensure_file() -> None:
    path = _current_results_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("[]\n", encoding="utf-8")


def load_results() -> list[dict[str, Any]]:
    _ensure_file()
    loaded = json.loads(_current_results_path().read_text(encoding="utf-8"))
    if not isinstance(loaded, list):
        return []
    return loaded


def save_results(rows: list[dict[str, Any]]) -> None:
    _ensure_file()
    _current_results_path().write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")


def append_result(result: dict[str, Any]) -> None:
    rows = load_results()
    rows.append(result)
    save_results(rows)


def latest_result(agent_id: str, version: str | None = None) -> dict[str, Any] | None:
    rows = load_results()
    candidates = [r for r in rows if r.get("agent_id") == agent_id]
    if version is not None:
        candidates = [r for r in candidates if r.get("version") == version]
    if not candidates:
        return None
    candidates.sort(key=lambda r: r.get("completed_at", ""), reverse=True)
    return candidates[0]
