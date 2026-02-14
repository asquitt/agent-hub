from __future__ import annotations

import hashlib
import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from slowapi.errors import RateLimitExceeded

from src.api.access_policy import access_mode, classify_route, evaluate_access, requires_idempotency
from src.api.auth import resolve_owner_from_headers
from src.api.route_helpers import append_warning_header, meter_warn, resolve_tenant_id, stable_error
from src.api.routes import (
    a2a_router,
    agents_router,
    approval_router,
    auth_routes_router,
    billing_router,
    capabilities_router,
    compliance_router,
    customer_router,
    delegation_router,
    discovery_router,
    federation_router,
    identity_router,
    identity_advanced_router,
    intent_router,
    knowledge_router,
    marketplace_router,
    misc_router,
    operator_router,
    procurement_router,
    provenance_router,
    runtime_router,
    oauth_router,
    system_router,
    tokens_router,
)
from src.idempotency import storage as idempotency_storage

_log = logging.getLogger("agenthub.app")


def _close_storage_connections() -> None:
    """Close all SQLite storage connections on shutdown."""
    closers = [
        ("identity", "src.identity.storage", "IdentityStorage"),
        ("runtime", "src.runtime.storage", "RuntimeStorage"),
        ("delegation", "src.delegation.storage", "DelegationStorage"),
        ("idempotency", "src.idempotency.storage", "IdempotencyStorage"),
    ]
    for name, module_path, class_name in closers:
        try:
            mod = __import__(module_path, fromlist=[class_name])
            cls = getattr(mod, class_name, None)
            if cls is None:
                continue
            instance = getattr(cls, "_instance", None)
            if instance is None:
                continue
            conn = getattr(instance, "_conn", None)
            if conn is not None:
                conn.close()
                _log.info("closed %s storage connection", name)
        except Exception:
            _log.warning("failed to close %s storage", name, exc_info=True)


@asynccontextmanager
async def _app_lifespan(_app: FastAPI):
    from src.api.auth import validate_auth_configuration
    from src.api.logging import setup_logging
    from src.federation import validate_federation_configuration
    from src.provenance.service import validate_provenance_configuration

    setup_logging()
    validate_auth_configuration()
    validate_federation_configuration()
    validate_provenance_configuration()
    yield
    # Graceful shutdown: close all SQLite connections
    _close_storage_connections()


app = FastAPI(title="AgentHub Registry Service", version="0.1.0", lifespan=_app_lifespan)

# --- Router registration ---
app.include_router(a2a_router)
app.include_router(system_router)
app.include_router(customer_router)
app.include_router(operator_router)
app.include_router(identity_router)
app.include_router(identity_advanced_router)
app.include_router(runtime_router)
app.include_router(agents_router)
app.include_router(auth_routes_router)
app.include_router(billing_router)
app.include_router(capabilities_router)
app.include_router(compliance_router)
app.include_router(delegation_router)
app.include_router(discovery_router)
app.include_router(federation_router)
app.include_router(knowledge_router)
app.include_router(marketplace_router)
app.include_router(misc_router)
app.include_router(procurement_router)
app.include_router(provenance_router)
app.include_router(tokens_router)
app.include_router(oauth_router)
app.include_router(approval_router)
app.include_router(intent_router)

# --- Production middleware ---

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("AGENTHUB_CORS_ORIGINS", "").split(",") if os.environ.get("AGENTHUB_CORS_ORIGINS") else [],
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["X-API-Key", "Authorization", "Content-Type", "Idempotency-Key", "X-Delegation-Token"],
    expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
)

# Rate limiting
from src.api.middleware import limiter, rate_limit_exceeded_handler as _rl_handler  # noqa: E402

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rl_handler)

# Request logging + X-Request-ID
from src.api.middleware import RequestLoggingMiddleware  # noqa: E402

app.add_middleware(RequestLoggingMiddleware)

# Delegation chain middleware
from src.api.middleware_delegation import DelegationChainMiddleware  # noqa: E402

app.add_middleware(DelegationChainMiddleware)


# --- Access policy middleware ---


@app.middleware("http")
async def _agenthub_access_policy_middleware(request: Request, call_next):
    # CORS preflight (OPTIONS) never carries auth headers — let it through
    if request.method.upper() == "OPTIONS":
        return await call_next(request)

    method = request.method.upper()
    path = request.url.path
    tenant_id = resolve_tenant_id(request.headers.get("X-Tenant-ID"))
    classification = classify_route(method, path)
    mode = access_mode()

    from fastapi import HTTPException

    auth_error: HTTPException | None = None
    owner: str | None = None
    try:
        owner = resolve_owner_from_headers(
            x_api_key=request.headers.get("X-API-Key"),
            authorization=request.headers.get("Authorization"),
            x_delegation_token=request.headers.get("X-Delegation-Token"),
            strict=False,
        )
    except HTTPException as exc:
        auth_error = exc

    request.state.agenthub_owner = owner
    request.state.agenthub_tenant_id = tenant_id

    violation = evaluate_access(classification=classification, owner=owner, tenant_id=tenant_id)
    if auth_error is not None and classification != "public" and owner is None:
        violation_code = "auth.invalid"
        violation_message = str(auth_error.detail)
    elif violation is not None:
        violation_code = violation.code
        violation_message = violation.message
    else:
        violation_code = None
        violation_message = None

    if violation_code is not None and mode == "enforce":
        status_code = 401 if violation_code in {"auth.required", "auth.invalid"} else 403
        error_response = stable_error(status_code, violation_code, violation_message or "request not permitted")
        # Add CORS headers so browsers can read the error
        origin = request.headers.get("origin", "")
        if origin:
            allowed = os.environ.get("AGENTHUB_CORS_ORIGINS", "*")
            if allowed == "*" or origin in allowed.split(","):
                error_response.headers["Access-Control-Allow-Origin"] = origin if allowed != "*" else "*"
        return error_response

    response = await call_next(request)
    if violation_code is not None:
        warning = f"{violation_code}:{violation_message}"
        append_warning_header(response, warning)
        meter_warn(
            actor=owner or "anonymous",
            kind="access.warn",
            method=method,
            path=path,
            tenant_id=tenant_id,
            code=violation_code,
            message=violation_message or "request not permitted",
        )
    return response


# --- Idempotency middleware ---


@app.middleware("http")
async def _agenthub_idempotency_middleware(request: Request, call_next):
    method = request.method.upper()
    path = request.url.path
    if not requires_idempotency(method, path):
        return await call_next(request)

    mode = access_mode()
    tenant_id = resolve_tenant_id(request.headers.get("X-Tenant-ID"))
    owner = getattr(request.state, "agenthub_owner", None)
    if owner is None:
        owner = resolve_owner_from_headers(
            x_api_key=request.headers.get("X-API-Key"),
            authorization=request.headers.get("Authorization"),
            x_delegation_token=request.headers.get("X-Delegation-Token"),
            strict=False,
        )
    actor = owner or "anonymous"

    key = request.headers.get("Idempotency-Key")
    if key is None or not key.strip():
        if mode == "enforce":
            return stable_error(400, "idempotency.missing_key", "missing Idempotency-Key header")
        response = await call_next(request)
        append_warning_header(response, "idempotency.missing_key:missing Idempotency-Key header")
        meter_warn(
            actor=actor,
            kind="idempotency.warn",
            method=method,
            path=path,
            tenant_id=tenant_id,
            code="idempotency.missing_key",
            message="missing Idempotency-Key header",
        )
        return response

    key = key.strip()
    body = await request.body()
    hash_input = b"|".join([method.encode("utf-8"), path.encode("utf-8"), request.url.query.encode("utf-8"), body])
    request_hash = hashlib.sha256(hash_input).hexdigest()
    reservation = idempotency_storage.reserve(
        tenant_id=tenant_id,
        actor=actor,
        method=method,
        route=path,
        idempotency_key=key,
        request_hash=request_hash,
    )
    state = str(reservation.get("state", "reserved"))
    if state == "mismatch":
        return stable_error(409, "idempotency.key_reused_with_different_payload", "idempotency key reuse with different payload")
    if state == "pending":
        return stable_error(409, "idempotency.in_progress", "request with idempotency key is still in progress")
    if state == "response":
        replay = reservation["response"]
        replay_response = Response(
            content=replay["body"],
            status_code=int(replay.get("status_code", 200)),
            media_type=str(replay.get("content_type") or "application/json"),
        )
        for header_name, value in dict(replay.get("headers", {})).items():
            if header_name.lower() == "content-length":
                continue
            replay_response.headers[str(header_name)] = str(value)
        replay_response.headers["X-AgentHub-Idempotent-Replay"] = "true"
        return replay_response

    async def _receive() -> dict[str, Any]:
        return {"type": "http.request", "body": body, "more_body": False}

    request_with_body = Request(request.scope, _receive)
    try:
        response = await call_next(request_with_body)
        response_body = b""
        async for chunk in response.body_iterator:
            response_body += chunk
        content_type = response.headers.get("content-type", "application/json")
        response_headers = {k: v for k, v in response.headers.items()}

        if response.status_code < 300:
            # Only cache successful responses — 4xx should be retryable with corrected payload
            idempotency_storage.finalize(
                tenant_id=tenant_id,
                actor=actor,
                method=method,
                route=path,
                idempotency_key=key,
                status_code=response.status_code,
                content_type=content_type,
                headers=response_headers,
                body=response_body,
            )
        else:
            idempotency_storage.clear(
                tenant_id=tenant_id,
                actor=actor,
                method=method,
                route=path,
                idempotency_key=key,
            )

        final_response = Response(
            content=response_body,
            status_code=response.status_code,
            media_type=response.media_type,
            background=response.background,
        )
        for header_name, value in response_headers.items():
            if header_name.lower() == "content-length":
                continue
            final_response.headers[header_name] = value
        return final_response
    except Exception:
        idempotency_storage.clear(
            tenant_id=tenant_id,
            actor=actor,
            method=method,
            route=path,
            idempotency_key=key,
        )
        raise
