from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import UTC, datetime
from typing import Any

from fastapi import Header, HTTPException

API_KEYS = {
    "dev-owner-key": "owner-dev",
    "partner-owner-key": "owner-partner",
    "platform-owner-key": "owner-platform",
}

DEFAULT_TOKEN_TTL_SECONDS = 1800
MAX_TOKEN_TTL_SECONDS = 86400


def _now_epoch() -> int:
    return int(datetime.now(UTC).timestamp())


def _token_secret() -> bytes:
    secret = os.getenv("AGENTHUB_AUTH_TOKEN_SECRET", "agenthub-dev-token-secret")
    return secret.encode("utf-8")


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(encoded: str) -> bytes:
    padding = "=" * ((4 - len(encoded) % 4) % 4)
    return base64.urlsafe_b64decode((encoded + padding).encode("utf-8"))


def _sign(body: str) -> str:
    return hmac.new(_token_secret(), body.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_scoped_token(owner: str, scopes: list[str], ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS) -> dict[str, Any]:
    ttl = max(1, min(int(ttl_seconds), MAX_TOKEN_TTL_SECONDS))
    now = _now_epoch()
    payload = {
        "sub": owner,
        "scopes": sorted({str(scope).strip() for scope in scopes if str(scope).strip()}),
        "iat": now,
        "exp": now + ttl,
    }
    body = _b64url_encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    token = f"{body}.{_sign(body)}"
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_at": datetime.fromtimestamp(payload["exp"], tz=UTC).isoformat(),
        "scopes": payload["scopes"],
        "subject": payload["sub"],
    }


def verify_scoped_token(token: str) -> dict[str, Any]:
    try:
        body, signature = token.split(".", 1)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid bearer token format") from exc

    expected = _sign(body)
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=401, detail="invalid bearer token signature")

    try:
        payload = json.loads(_b64url_decode(body).decode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive parse guard
        raise HTTPException(status_code=401, detail="invalid bearer token payload") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=401, detail="invalid bearer token payload")
    if "sub" not in payload or "exp" not in payload:
        raise HTTPException(status_code=401, detail="invalid bearer token claims")
    if int(payload["exp"]) < _now_epoch():
        raise HTTPException(status_code=401, detail="bearer token expired")
    scopes = payload.get("scopes", [])
    if not isinstance(scopes, list):
        raise HTTPException(status_code=401, detail="invalid bearer token scopes")
    payload["scopes"] = [str(scope) for scope in scopes]
    payload["sub"] = str(payload["sub"])
    return payload


def _owner_from_api_key(x_api_key: str | None) -> str | None:
    if not x_api_key:
        return None
    return API_KEYS.get(x_api_key)


def _owner_and_scopes_from_authorization(authorization: str | None) -> tuple[str, list[str]] | None:
    if not authorization:
        return None
    prefix = "bearer "
    if not authorization.lower().startswith(prefix):
        raise HTTPException(status_code=401, detail="invalid authorization scheme")
    token = authorization[len(prefix) :].strip()
    claims = verify_scoped_token(token)
    return claims["sub"], claims.get("scopes", [])


def require_api_key_owner(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> str:
    owner = _owner_from_api_key(x_api_key)
    if owner is None:
        raise HTTPException(status_code=401, detail="missing or invalid API key")
    return owner


def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> str:
    owner = _owner_from_api_key(x_api_key)
    if owner is not None:
        return owner
    token_auth = _owner_and_scopes_from_authorization(authorization)
    if token_auth is not None:
        return token_auth[0]
    raise HTTPException(status_code=401, detail="missing or invalid authentication")


def require_scope(scope: str):
    normalized_scope = scope.strip()

    def _dependency(
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> str:
        owner = _owner_from_api_key(x_api_key)
        if owner is not None:
            return owner

        token_auth = _owner_and_scopes_from_authorization(authorization)
        if token_auth is None:
            raise HTTPException(status_code=401, detail="missing or invalid authentication")
        token_owner, scopes = token_auth
        if normalized_scope in scopes or "*" in scopes:
            return token_owner
        raise HTTPException(status_code=403, detail=f"missing required scope: {normalized_scope}")

    return _dependency
