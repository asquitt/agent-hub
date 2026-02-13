from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter

ROOT = Path(__file__).resolve().parents[3]

router = APIRouter()


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/.well-known/agent-card.json")
def discovery_agent_card() -> dict[str, object]:
    card_path = ROOT / ".well-known" / "agent-card.json"
    return json.loads(card_path.read_text(encoding="utf-8"))
