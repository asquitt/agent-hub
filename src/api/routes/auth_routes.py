"""Auth token issuance route."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from src.api.auth import issue_scoped_token, require_api_key_owner
from src.api.models import AuthTokenIssueRequest

router = APIRouter(tags=["auth"])


@router.post("/v1/auth/tokens")
def issue_auth_token(
    request: AuthTokenIssueRequest,
    owner: str = Depends(require_api_key_owner),
) -> dict[str, Any]:
    return issue_scoped_token(owner=owner, scopes=request.scopes, ttl_seconds=request.ttl_seconds)
