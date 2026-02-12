from __future__ import annotations

from fastapi import Header, HTTPException

API_KEYS = {
    "dev-owner-key": "owner-dev",
    "partner-owner-key": "owner-partner",
    "platform-owner-key": "owner-platform",
}


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> str:
    if not x_api_key or x_api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="missing or invalid API key")
    return API_KEYS[x_api_key]
