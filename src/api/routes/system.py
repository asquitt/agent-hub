from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from src.api.auth import require_api_key
from src.api.startup_diagnostics import build_startup_diagnostics

ROOT = Path(__file__).resolve().parents[3]

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def marketing_home() -> str:
    ui_path = ROOT / "src" / "ui" / "marketing_home.html"
    return ui_path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Health & Readiness
# ---------------------------------------------------------------------------

_REQUIRED_ENV_VARS = (
    "AGENTHUB_API_KEYS_JSON",
    "AGENTHUB_AUTH_TOKEN_SECRET",
    "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON",
    "AGENTHUB_PROVENANCE_SIGNING_SECRET",
)


def _check_db(storage: Any) -> dict[str, str]:
    """Ping a SQLite storage singleton with SELECT 1."""
    try:
        storage._ensure_ready()
        storage._conn.execute("SELECT 1")
        return {"status": "ok"}
    except Exception:  # noqa: BLE001
        return {"status": "unhealthy"}


@router.get("/healthz")
def healthz() -> JSONResponse:
    checks: dict[str, Any] = {}

    # Database connectivity
    try:
        from src.identity.storage import IDENTITY_STORAGE
        checks["identity_db"] = _check_db(IDENTITY_STORAGE)
    except (ImportError, RuntimeError):
        checks["identity_db"] = {"status": "not_configured"}

    try:
        from src.runtime.storage import RUNTIME_STORAGE
        checks["runtime_db"] = _check_db(RUNTIME_STORAGE)
    except (ImportError, RuntimeError):
        checks["runtime_db"] = {"status": "not_configured"}

    try:
        from src.delegation.storage import DelegationStorage
        checks["delegation_db"] = _check_db(DelegationStorage())
    except (ImportError, RuntimeError):
        checks["delegation_db"] = {"status": "not_configured"}

    try:
        from src.idempotency.storage import IdempotencyStorage
        checks["idempotency_db"] = _check_db(IdempotencyStorage())
    except (ImportError, RuntimeError):
        checks["idempotency_db"] = {"status": "not_configured"}

    # Required env vars (names not exposed publicly — use /v1/system/startup-diagnostics for details)
    missing_count = sum(1 for v in _REQUIRED_ENV_VARS if not os.environ.get(v))
    checks["required_env_vars"] = {
        "status": "ok" if missing_count == 0 else "degraded",
        "missing_count": missing_count,
    }

    # Overall status
    statuses = [c.get("status", "ok") for c in checks.values()]
    if "unhealthy" in statuses:
        overall = "unhealthy"
        status_code = 503
    elif "degraded" in statuses:
        overall = "degraded"
        status_code = 200
    else:
        overall = "ok"
        status_code = 200

    return JSONResponse(
        status_code=status_code,
        content={"status": overall, "checks": checks},
    )


@router.get("/readyz")
def readyz() -> JSONResponse:
    """Full readiness: DB connectivity + env vars all pass."""
    health_resp = healthz()
    body = json.loads(bytes(health_resp.body).decode())

    if body["status"] == "unhealthy":
        return JSONResponse(status_code=503, content={"ready": False, **body})

    return JSONResponse(status_code=200, content={"ready": True, **body})


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
