"""Production middleware: rate limiting, request timeouts, request logging."""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from typing import Any

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from src.api.logging import get_logger

logger = get_logger("middleware")

# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------

_DEFAULT_RATE = os.environ.get("AGENTHUB_RATE_LIMIT_DEFAULT", "100/minute")

# Exempt paths (no rate limiting)
_EXEMPT_PREFIXES = ("/healthz", "/readyz", "/.well-known", "/docs", "/openapi.json")


def _key_func(request: Request) -> str:
    """Key by API key header, falling back to client IP."""
    api_key = request.headers.get("x-api-key", "")
    if api_key:
        return api_key
    return get_remote_address(request)


limiter = Limiter(key_func=_key_func, default_limits=[_DEFAULT_RATE])


def rate_limit_exceeded_handler(_request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"detail": f"rate limit exceeded: {exc.detail}"},
    )


# ---------------------------------------------------------------------------
# Request Timeout
# ---------------------------------------------------------------------------

_TIMEOUT_SECONDS = int(os.environ.get("AGENTHUB_REQUEST_TIMEOUT_SECONDS", "30"))


class RequestTimeoutMiddleware(BaseHTTPMiddleware):
    """Return 504 if request processing exceeds timeout."""

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if request.url.path in ("/healthz", "/readyz"):
            return await call_next(request)
        try:
            return await asyncio.wait_for(call_next(request), timeout=_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            return JSONResponse(
                status_code=504,
                content={"detail": f"request timed out after {_TIMEOUT_SECONDS}s"},
            )


# ---------------------------------------------------------------------------
# Request Logging + X-Request-ID
# ---------------------------------------------------------------------------


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Inject X-Request-ID and log request/response metadata."""

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        request.state.request_id = request_id

        start = time.monotonic()
        response: Response = await call_next(request)
        duration_ms = round((time.monotonic() - start) * 1000, 2)

        response.headers["X-Request-ID"] = request_id

        status = response.status_code
        log_data = {
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": status,
            "duration_ms": duration_ms,
        }

        if status >= 500:
            logger.error("request completed", extra=log_data)
        elif status >= 400:
            logger.warning("request completed", extra=log_data)
        else:
            logger.info("request completed", extra=log_data)

        return response
