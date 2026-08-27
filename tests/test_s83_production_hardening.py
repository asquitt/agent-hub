"""S83-S90: Production hardening tests."""

from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key-001": "test-owner"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-signing-secret-hardening")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-secret")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test-domain": "test-token"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-provenance-secret")
os.environ.setdefault("AGENTHUB_POLICY_SIGNING_SECRET", "test-policy-secret")
os.environ.setdefault("AGENTHUB_VAULT_KEY", "test-vault-key")

from starlette.testclient import TestClient

from src.api.app import app

HEADERS = {"X-API-Key": "test-key-001"}

client = TestClient(app)


# ---- CORS ----


def test_cors_headers_present():
    """CORS headers should be present on responses."""
    resp = client.options(
        "/healthz",
        headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" in resp.headers
    print("PASS: CORS headers present")


def test_cors_allows_custom_headers():
    """CORS should allow X-API-Key and other custom headers."""
    resp = client.options(
        "/v1/runtime/profiles",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-API-Key,Content-Type",
        },
    )
    allow_headers = resp.headers.get("access-control-allow-headers", "").lower()
    assert "x-api-key" in allow_headers
    assert "content-type" in allow_headers
    print("PASS: CORS allows custom headers")


def test_cors_allows_and_exposes_mcp_protocol_headers(monkeypatch):
    """Allowed browser MCP clients can complete preflight and read auth metadata."""
    origin = "https://app.example.com"
    monkeypatch.setenv("AGENTHUB_MCP_ALLOWED_ORIGINS_JSON", json.dumps([origin]))
    preflight = client.options(
        "/mcp",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": (
                "Authorization,Content-Type,MCP-Protocol-Version,X-Tenant-ID"
            ),
        },
    )
    challenge = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "browser-client", "version": "1.0.0"},
            },
        },
        headers={
            "Origin": origin,
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
    )

    assert preflight.status_code == 200, preflight.text
    allow_headers = preflight.headers["access-control-allow-headers"].lower()
    assert "mcp-protocol-version" in allow_headers
    assert "x-tenant-id" in allow_headers
    assert challenge.status_code == 401
    expose_headers = challenge.headers["access-control-expose-headers"].lower()
    assert "mcp-protocol-version" in expose_headers
    assert "www-authenticate" in expose_headers


# ---- Health Check ----


def test_healthz_is_dependency_free_liveness():
    """Liveness reports only whether the process can serve requests."""
    resp = client.get("/healthz")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"status": "ok"}
    print("PASS: healthz is dependency-free liveness")


def test_readyz_returns_dependency_checks():
    """Readiness reports database and required-configuration checks."""
    resp = client.get("/readyz")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["ready"] is True
    assert data["checks"]["required_env_vars"] == {"status": "ok", "missing_count": 0}
    assert data["checks"]["identity_db"]["status"] == "ok"
    assert data["checks"]["runtime_db"]["status"] == "ok"
    print("PASS: readyz verifies dependencies")


def test_readyz_returns_readiness():
    """Readiness check should return ready status."""
    resp = client.get("/readyz")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "ready" in data
    assert data["ready"] is True
    print("PASS: readyz returns readiness")


# ---- X-Request-ID ----


def test_request_id_injected():
    """Every response should have X-Request-ID header."""
    resp = client.get("/healthz")
    assert "x-request-id" in resp.headers
    assert len(resp.headers["x-request-id"]) > 0
    print("PASS: X-Request-ID injected")


def test_request_id_preserved():
    """If client sends X-Request-ID, it should be preserved."""
    resp = client.get("/healthz", headers={"X-Request-ID": "test-req-123"})
    assert resp.headers.get("x-request-id") == "test-req-123"
    print("PASS: X-Request-ID preserved from client")


# ---- Rate Limiting ----


def test_rate_limiter_configured():
    """Rate limiter should be configured on the app."""
    assert hasattr(app.state, "limiter")
    print("PASS: rate limiter configured")


# ---- Bare Exception Fix ----


def test_auth_uses_specific_exceptions():
    """Auth module should use specific exception types, not bare Exception."""
    import inspect
    from src.api import auth

    source = inspect.getsource(auth.verify_scoped_token)
    # Should NOT contain "except Exception"
    assert "except Exception" not in source
    # Should contain specific types
    assert "JSONDecodeError" in source or "ValueError" in source
    print("PASS: auth uses specific exception types")


def test_identity_storage_uses_sqlite_error():
    """Identity storage reset should use sqlite3.Error."""
    import inspect
    from src.identity.storage import IdentityStorage

    source = inspect.getsource(IdentityStorage.reset_for_tests)
    assert "sqlite3.Error" in source
    print("PASS: identity storage uses sqlite3.Error")


def test_runtime_storage_uses_sqlite_error():
    """Runtime storage reset should use sqlite3.Error."""
    import inspect
    from src.runtime.storage import RuntimeStorage

    source = inspect.getsource(RuntimeStorage.reset_for_tests)
    assert "sqlite3.Error" in source
    print("PASS: runtime storage uses sqlite3.Error")


# ---- Structured Logging ----


def test_logging_setup():
    """Structured logging should be configurable."""
    from src.api.logging import get_logger, setup_logging

    setup_logging()
    logger = get_logger("test")
    assert logger.name == "agenthub.test"
    print("PASS: structured logging setup")


# ---- Dockerfile ----


def test_dockerfile_has_healthcheck():
    """Dockerfile should include HEALTHCHECK directive."""
    from pathlib import Path

    dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile"
    content = dockerfile.read_text()
    assert "HEALTHCHECK" in content
    assert "USER appuser" in content
    assert "--timeout-keep-alive" in content
    print("PASS: Dockerfile hardened")


# ---- CI ----


def test_ci_runs_full_suite_and_blocking_dependency_audit():
    """CI must collect and run every Python test before a blocking audit."""
    from pathlib import Path

    ci = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "quality-gates.yml"
    content = ci.read_text()
    assert "python -m pytest --collect-only -q" in content
    assert "python -m pytest -q" in content
    assert "python -m pip_audit --strict --requirement requirements.txt" in content
    assert "pip-audit --strict || true" not in content
    print("PASS: CI runs the full suite and blocking security scan")


if __name__ == "__main__":
    test_cors_headers_present()
    test_cors_allows_custom_headers()
    test_healthz_is_dependency_free_liveness()
    test_readyz_returns_dependency_checks()
    test_readyz_returns_readiness()
    test_request_id_injected()
    test_request_id_preserved()
    test_rate_limiter_configured()
    test_auth_uses_specific_exceptions()
    test_identity_storage_uses_sqlite_error()
    test_runtime_storage_uses_sqlite_error()
    test_logging_setup()
    test_dockerfile_has_healthcheck()
    test_ci_runs_full_suite_and_blocking_dependency_audit()
    print("\nAll production hardening tests passed!")
