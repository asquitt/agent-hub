from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from src.api.auth import require_api_key
from src.api.startup_diagnostics import REQUIRED_ENV_VARS, build_startup_diagnostics

ROOT = Path(__file__).resolve().parents[3]

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def marketing_home() -> str:
    ui_path = ROOT / "src" / "ui" / "marketing_home.html"
    return ui_path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Health & Readiness
# ---------------------------------------------------------------------------

def _check_db(storage: Any) -> dict[str, str]:
    """Ping a SQLite storage singleton with SELECT 1."""
    try:
        storage._ensure_ready()
        storage._conn.execute("SELECT 1")
        return {"status": "ok"}
    except Exception:  # noqa: BLE001
        return {"status": "unhealthy"}


def _check_identity_quarantine(storage: Any) -> dict[str, Any]:
    try:
        quarantined_count = storage.count_quarantined_identities()
        return {
            "status": "ok" if quarantined_count == 0 else "blocked",
            "quarantined_count": quarantined_count,
        }
    except Exception:  # noqa: BLE001
        return {"status": "unhealthy"}


def _readiness_checks() -> dict[str, Any]:
    checks: dict[str, Any] = {}

    # Database connectivity
    try:
        from src.identity.storage import IDENTITY_STORAGE
        checks["identity_db"] = _check_db(IDENTITY_STORAGE)
        checks["identity_quarantine"] = _check_identity_quarantine(IDENTITY_STORAGE)
    except (ImportError, RuntimeError):
        checks["identity_db"] = {"status": "not_configured"}
        checks["identity_quarantine"] = {"status": "not_configured"}

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
    missing_count = sum(1 for variable in REQUIRED_ENV_VARS if not str(os.environ.get(variable, "")).strip())
    checks["required_env_vars"] = {
        "status": "ok" if missing_count == 0 else "degraded",
        "missing_count": missing_count,
    }

    return checks


def _readiness_payload() -> dict[str, Any]:
    checks = _readiness_checks()

    statuses = [c.get("status", "ok") for c in checks.values()]
    if "unhealthy" in statuses:
        overall = "unhealthy"
    elif any(status != "ok" for status in statuses):
        overall = "degraded"
    else:
        overall = "ok"

    return {"status": overall, "checks": checks}


@router.get("/healthz")
def healthz() -> dict[str, str]:
    """Process liveness only; dependency failures belong to readiness."""
    return {"status": "ok"}



@router.get("/readyz")
def readyz() -> JSONResponse:
    """Full readiness: DB connectivity + env vars all pass."""
    body = _readiness_payload()
    ready = body["status"] == "ok"
    return JSONResponse(status_code=200 if ready else 503, content={"ready": ready, **body})


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
