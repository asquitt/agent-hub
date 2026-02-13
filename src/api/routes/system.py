from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from src.api.auth import require_api_key
from src.api.startup_diagnostics import build_startup_diagnostics

ROOT = Path(__file__).resolve().parents[3]

router = APIRouter()


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/.well-known/agent-card.json")
def discovery_agent_card() -> dict[str, object]:
    card_path = ROOT / ".well-known" / "agent-card.json"
    return json.loads(card_path.read_text(encoding="utf-8"))


@router.get("/v1/system/startup-diagnostics")
def startup_diagnostics(owner: str = Depends(require_api_key)) -> dict[str, object]:
    if owner not in {"owner-dev", "owner-platform"}:
        raise HTTPException(
            status_code=403,
            detail={"code": "auth.admin_required", "message": "admin role required"},
        )
    return build_startup_diagnostics()
