from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.common.json_store import read_json_list, write_json_list

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PACKS = ROOT / "data" / "procurement" / "policy_packs.json"
DEFAULT_APPROVALS = ROOT / "data" / "procurement" / "approvals.json"
DEFAULT_EXCEPTIONS = ROOT / "data" / "procurement" / "exceptions.json"
DEFAULT_AUDIT = ROOT / "data" / "procurement" / "audit.json"


def _path(name: str) -> Path:
    if name == "policy_packs":
        return Path(os.getenv("AGENTHUB_PROCUREMENT_POLICY_PACKS_PATH", str(DEFAULT_POLICY_PACKS)))
    if name == "approvals":
        return Path(os.getenv("AGENTHUB_PROCUREMENT_APPROVALS_PATH", str(DEFAULT_APPROVALS)))
    if name == "exceptions":
        return Path(os.getenv("AGENTHUB_PROCUREMENT_EXCEPTIONS_PATH", str(DEFAULT_EXCEPTIONS)))
    if name == "audit":
        return Path(os.getenv("AGENTHUB_PROCUREMENT_AUDIT_PATH", str(DEFAULT_AUDIT)))
    raise ValueError(f"unsupported procurement storage name: {name}")


def load(name: str) -> list[dict[str, Any]]:
    path = _path(name)
    return read_json_list(path)


def save(name: str, rows: list[dict[str, Any]]) -> None:
    path = _path(name)
    write_json_list(path, rows)
