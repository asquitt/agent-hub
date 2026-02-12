from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

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
