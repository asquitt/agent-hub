"""Behavioral coverage for HTTP reliability middleware and probes."""

from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def reliability_app(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("behavioral-http-controls")
    required = {
        "AGENTHUB_API_KEYS_JSON": '{"dev-owner-key":"owner-dev"}',
        "AGENTHUB_AUTH_TOKEN_SECRET": "test-auth-secret",
        "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON": '{"test-domain":"test-token"}',
        "AGENTHUB_IDENTITY_SIGNING_SECRET": "test-identity-secret",
        "AGENTHUB_POLICY_SIGNING_SECRET": "test-policy-secret",
        "AGENTHUB_PROVENANCE_SIGNING_SECRET": "test-provenance-secret",
        "AGENTHUB_VAULT_KEY": "test-vault-key",
        "AGENTHUB_RATE_LIMIT_DEFAULT": "2/minute",
        "AGENTHUB_REQUEST_TIMEOUT_SECONDS": "0.02",
    }
    storage_paths = {
        "AGENTHUB_REGISTRY_DB_PATH": root / "registry.db",
        "AGENTHUB_IDENTITY_DB_PATH": root / "identity.db",
        "AGENTHUB_RUNTIME_DB_PATH": root / "runtime.db",
        "AGENTHUB_DELEGATION_DB_PATH": root / "delegation.db",
        "AGENTHUB_IDEMPOTENCY_DB_PATH": root / "idempotency.db",
        "AGENTHUB_BILLING_DB_PATH": root / "billing.db",
        "AGENTHUB_COST_DB_PATH": root / "cost.db",
        "AGENTHUB_COMPLIANCE_DB_PATH": root / "compliance.db",
        "AGENTHUB_DEVHUB_DB_PATH": root / "devhub.db",
        "AGENTHUB_EVAL_DB_PATH": root / "eval.db",
        "AGENTHUB_FEDERATION_DB_PATH": root / "federation.db",
        "AGENTHUB_KNOWLEDGE_DB_PATH": root / "knowledge.db",
        "AGENTHUB_LEASE_DB_PATH": root / "lease.db",
        "AGENTHUB_MARKETPLACE_DB_PATH": root / "marketplace.db",
        "AGENTHUB_OPERATOR_DIAGNOSTICS_DB_PATH": root / "operator.db",
        "AGENTHUB_PROCUREMENT_DB_PATH": root / "procurement.db",
        "AGENTHUB_TRUST_DB_PATH": root / "trust.db",
    }
    environment = {**required, **{key: str(path) for key, path in storage_paths.items()}}

    with patch.dict(os.environ, environment, clear=False):
        from src.api.app import app
        from src.api.middleware import limiter

        original_routes = list(app.router.routes)

        async def fast_probe() -> dict[str, bool]:
            return {"ok": True}

        async def slow_probe() -> dict[str, bool]:
            await asyncio.sleep(0.1)
            return {"ok": True}

        app.add_api_route("/__reliability__/fast", fast_probe, methods=["GET"], include_in_schema=False)
        app.add_api_route("/__reliability__/slow", slow_probe, methods=["GET"], include_in_schema=False)
        limiter.reset()
        yield app
        limiter.reset()
        app.router.routes[:] = original_routes


def test_default_rate_limit_returns_429(reliability_app) -> None:
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


def test_request_timeout_returns_504(reliability_app) -> None:
    client = TestClient(reliability_app)
    try:
        response = client.get(
            "/__reliability__/slow",
            headers={"X-API-Key": "behavioral-timeout-key"},
        )
    finally:
        client.close()

    assert response.status_code == 504
    assert response.json() == {"detail": "request timed out after 0.02s"}
    assert response.headers.get("X-Request-ID")


def test_missing_required_configuration_is_not_ready(
    reliability_app,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.api.startup_diagnostics import REQUIRED_ENV_VARS

    for variable in REQUIRED_ENV_VARS:
        monkeypatch.delenv(variable, raising=False)

    client = TestClient(reliability_app)
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
