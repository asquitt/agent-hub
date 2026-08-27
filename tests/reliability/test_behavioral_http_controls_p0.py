"""Behavioral coverage for HTTP reliability middleware and probes."""

from __future__ import annotations

import asyncio
from typing import Any, cast
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware


@pytest.fixture()
def reliability_app() -> FastAPI:
    from src.api.middleware import (
        RequestLoggingMiddleware,
        RequestTimeoutMiddleware,
        limiter,
        rate_limit_exceeded_handler,
    )

    app = FastAPI()
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, cast(Any, rate_limit_exceeded_handler))

    @app.get("/__reliability__/fast")
    @limiter.limit("2/minute")
    async def fast_probe(request: Request) -> dict[str, bool]:
        return {"ok": True}

    @app.get("/__reliability__/slow")
    async def slow_probe() -> dict[str, bool]:
        await asyncio.sleep(0.75)
        return {"ok": True}

    app.add_middleware(SlowAPIMiddleware)
    app.add_middleware(RequestTimeoutMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    return app


def test_rate_limit_returns_429(reliability_app: FastAPI) -> None:
    from src.api.middleware import limiter

    limiter.reset()
    client = TestClient(reliability_app)
    try:
        headers = {"X-API-Key": "behavioral-rate-limit-key"}
        responses = [client.get("/__reliability__/fast", headers=headers) for _ in range(3)]
    finally:
        client.close()

    assert [response.status_code for response in responses] == [200, 200, 429]
    assert "rate limit exceeded" in responses[-1].json()["detail"]
    assert responses[-1].headers.get("X-Request-ID")


def test_request_timeout_returns_504(reliability_app: FastAPI) -> None:
    with patch("src.api.middleware._TIMEOUT_SECONDS", 0.5):
        client = TestClient(reliability_app)
        try:
            response = client.get(
                "/__reliability__/slow",
                headers={"X-API-Key": "behavioral-timeout-key"},
            )
        finally:
            client.close()

    assert response.status_code == 504
    assert response.json() == {"detail": "request timed out after 0.5s"}
    assert response.headers.get("X-Request-ID")


def test_missing_required_configuration_is_not_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.api.app import app
    from src.api.startup_diagnostics import REQUIRED_ENV_VARS

    for variable in REQUIRED_ENV_VARS:
        monkeypatch.delenv(variable, raising=False)

    client = TestClient(app)
    try:
        liveness_responses = [client.get("/healthz") for _ in range(4)]
        readiness = client.get("/readyz")
    finally:
        client.close()

    assert all(response.status_code == 200 for response in liveness_responses)
    assert all(response.json() == {"status": "ok"} for response in liveness_responses)
    assert readiness.status_code == 503
    assert readiness.json()["ready"] is False
    assert readiness.json()["status"] == "degraded"
    assert readiness.json()["checks"]["required_env_vars"] == {
        "status": "degraded",
        "missing_count": len(REQUIRED_ENV_VARS),
    }
