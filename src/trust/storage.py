from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.common.json_store import read_json_list, write_json_list

ROOT = Path(__file__).resolve().parents[2]
TRUST_DIR = ROOT / "data" / "trust"
DEFAULT_FILES = {
    "usage_events": TRUST_DIR / "usage_events.json",
    "reviews": TRUST_DIR / "reviews.json",
    "security_audits": TRUST_DIR / "security_audits.json",
    "incidents": TRUST_DIR / "incidents.json",
    "publisher_profiles": TRUST_DIR / "publisher_profiles.json",
    "interaction_graph": TRUST_DIR / "interaction_graph.json",
    "scores": TRUST_DIR / "scores.json",
}


def _path(name: str) -> Path:
    override = os.getenv(f"AGENTHUB_TRUST_{name.upper()}_PATH")
    return Path(override) if override else DEFAULT_FILES[name]


def load(name: str) -> list[dict[str, Any]]:
    return read_json_list(_path(name))


def save(name: str, rows: list[dict[str, Any]]) -> None:
    write_json_list(_path(name), rows)


def append(name: str, row: dict[str, Any]) -> None:
    rows = load(name)
    rows.append(row)
    save(name, rows)


def upsert_score(score_row: dict[str, Any]) -> None:
    rows = load("scores")
    agent_id = score_row.get("agent_id")
    replaced = False
    for idx, row in enumerate(rows):
        if row.get("agent_id") == agent_id:
            rows[idx] = score_row
            replaced = True
            break
    if not replaced:
        rows.append(score_row)
    save("scores", rows)


def get_score(agent_id: str) -> dict[str, Any] | None:
    for row in load("scores"):
        if row.get("agent_id") == agent_id:
            return row
    return None
