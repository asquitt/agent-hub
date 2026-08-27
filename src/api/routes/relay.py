from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import AuthContext, resolve_auth_context
from src.relay.defaults import RELAY_SERVICE
from src.relay.receipts import receipt_public_jwk, verify_receipt
from src.relay.service import RelayServiceError

router = APIRouter(prefix="/v1/relay", tags=["governed-mcp-relay"])


class ImportTargetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(min_length=1, max_length=128)


class RelayCallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(min_length=1, max_length=128)
    capability_token: dict[str, Any]
    arguments: dict[str, Any]


class RelayBudgetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_budget_usd: float = Field(gt=0, allow_inf_nan=False)


class RelayEnabledRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool


class ReceiptVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    receipt: dict[str, Any]


def _context(request: Request) -> AuthContext:
    context = getattr(request.state, "agenthub_auth_context", None)
    if not isinstance(context, AuthContext):
        raise HTTPException(
            status_code=401,
            detail={"code": "auth.required", "message": "authentication required"},
        )
    return context


def _relay_error(exc: RelayServiceError) -> HTTPException:
    detail: dict[str, Any] = {"code": exc.code, "message": str(exc)}
    if exc.record is not None:
        detail["invocation"] = exc.record
    return HTTPException(status_code=exc.status_code, detail=detail)


@router.post("/mcp/import")
async def import_mcp_target(
    body: ImportTargetRequest, request: Request
) -> dict[str, Any]:
    try:
        return await RELAY_SERVICE.import_target(
            body.target_id, actor=_context(request)
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "relay.target_not_found",
                "message": "relay target not found",
            },
        ) from exc
    except RelayServiceError as exc:
        raise _relay_error(exc) from exc


@router.put("/budgets/{capability_token_id}")
def set_relay_budget(
    capability_token_id: str, body: RelayBudgetRequest, request: Request
) -> dict[str, Any]:
    try:
        return RELAY_SERVICE.set_budget(
            capability_token_id=capability_token_id,
            max_budget_usd=body.max_budget_usd,
            actor=_context(request),
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "relay.capability_not_found",
                "message": "capability token not found",
            },
        ) from exc
    except (PermissionError, ValueError) as exc:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "relay.budget_denied",
                "message": "relay budget update denied",
            },
        ) from exc


@router.put("/mcp/targets/{target_id}/enabled")
def set_relay_target_enabled(
    target_id: str, body: RelayEnabledRequest, request: Request
) -> dict[str, Any]:
    try:
        return RELAY_SERVICE.set_target_enabled(
            target_id, enabled=body.enabled, actor=_context(request)
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "relay.target_not_found",
                "message": "relay target not found",
            },
        ) from exc
    except RelayServiceError as exc:
        raise _relay_error(exc) from exc


@router.post("/mcp/call")
async def call_mcp_tool(body: RelayCallRequest, request: Request) -> dict[str, Any]:
    idempotency_key = str(request.headers.get("Idempotency-Key", "")).strip()
    tenant_id = str(getattr(request.state, "agenthub_tenant_id", "tenant-default"))
    x_api_key = request.headers.get("X-API-Key")
    authorization = request.headers.get("Authorization")
    delegation_token = request.headers.get("X-Delegation-Token")

    def reauthenticate() -> object:
        context = resolve_auth_context(
            x_api_key=x_api_key,
            authorization=authorization,
            x_delegation_token=delegation_token,
            tenant_id=tenant_id,
        )
        if context is None:
            raise HTTPException(status_code=401, detail="authentication required")
        return context

    try:
        return await RELAY_SERVICE.invoke(
            target_id=body.target_id,
            capability_token=body.capability_token,
            arguments=body.arguments,
            idempotency_key=idempotency_key,
            source_ip=request.client.host if request.client is not None else None,
            reauthenticate=reauthenticate,
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "relay.target_not_found",
                "message": "relay target not found",
            },
        ) from exc
    except RelayServiceError as exc:
        raise _relay_error(exc) from exc


@router.get("/mcp/calls/{invocation_id}")
def get_relay_call(invocation_id: str, request: Request) -> dict[str, Any]:
    try:
        return RELAY_SERVICE.get_invocation(invocation_id, actor=_context(request))
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "relay.invocation_not_found",
                "message": "relay invocation not found",
            },
        ) from exc


@router.get("/mcp/receipts/{invocation_id}")
def get_relay_receipt(invocation_id: str, request: Request) -> dict[str, Any]:
    record = get_relay_call(invocation_id, request)
    receipt = record.get("receipt")
    if not isinstance(receipt, dict) or not receipt:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "relay.receipt_pending",
                "message": "relay receipt is not finalized",
            },
        )
    return receipt


@router.get("/receipt-keys/current")
def get_receipt_public_key() -> dict[str, str]:
    try:
        return receipt_public_jwk()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "relay.receipt_key_unavailable",
                "message": "relay receipt verification key is unavailable",
            },
        ) from exc


@router.post("/receipts/verify")
def verify_relay_receipt(body: ReceiptVerificationRequest) -> dict[str, Any]:
    try:
        trusted_jwk = receipt_public_jwk()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "relay.receipt_key_unavailable",
                "message": "relay receipt verification key is unavailable",
            },
        ) from exc
    return verify_receipt(body.receipt, trusted_jwk)
