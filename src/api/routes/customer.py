from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import HTMLResponse

from src.api.auth import resolve_owner_from_headers
from src.api.customer_ui_policy import customer_ui_allowed_owners, customer_ui_enabled, customer_ui_require_auth

ROOT = Path(__file__).resolve().parents[3]

router = APIRouter()


@router.get("/operator", response_class=HTMLResponse)
def operator_console() -> str:
    ui_path = ROOT / "src" / "ui" / "operator_dashboard.html"
    return ui_path.read_text(encoding="utf-8")


@router.get("/operator/versioning", response_class=HTMLResponse)
def operator_versioning_console() -> str:
    ui_path = ROOT / "src" / "ui" / "version_compare.html"
    return ui_path.read_text(encoding="utf-8")


@router.get("/customer", response_class=HTMLResponse)
def customer_journey_console(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> str:
    if not customer_ui_enabled():
        raise HTTPException(status_code=404, detail="not found")

    if customer_ui_require_auth():
        owner = resolve_owner_from_headers(
            x_api_key=x_api_key,
            authorization=authorization,
            strict=True,
        )
        if owner is None:
            raise HTTPException(status_code=401, detail="authentication required")
        if owner not in customer_ui_allowed_owners():
            raise HTTPException(status_code=403, detail="actor not permitted for customer ui")

    ui_path = ROOT / "src" / "ui" / "customer_journey.html"
    return ui_path.read_text(encoding="utf-8")
