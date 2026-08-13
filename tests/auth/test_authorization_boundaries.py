from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.access_policy import route_policy_map
from src.api.app import app
from src.api.auth import AuthContext, require_api_key
from src.identity import storage as identity_storage


@pytest.fixture()
def authorization_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "enforce")
    monkeypatch.setenv(
        "AGENTHUB_API_KEYS_JSON",
        json.dumps(
            {
                "owner-a-key": {"owner": "owner-a", "scopes": ["*"], "roles": ["member"]},
                "owner-b-key": {"owner": "owner-b", "scopes": ["*"], "roles": ["member"]},
                "read-only-key": {"owner": "owner-a", "scopes": ["read"], "roles": ["member"]},
                "token-issuer-key": {"owner": "owner-a", "scopes": ["auth.write"], "roles": ["member"]},
            }
        ),
    )
    monkeypatch.setenv("AGENTHUB_AUTH_TOKEN_SECRET", "authorization-boundary-token-secret")
    monkeypatch.setenv(
        "AGENTHUB_OWNER_TENANTS_JSON",
        json.dumps({"owner-a": ["tenant-a"], "owner-b": ["tenant-a"]}),
    )
    identity_db = tmp_path / "identity.db"
    monkeypatch.setenv("AGENTHUB_IDENTITY_DB_PATH", str(identity_db))
    identity_storage.reset_for_tests(db_path=identity_db)


def _headers(api_key: str, tenant_id: str = "tenant-a") -> dict[str, str]:
    return {"X-API-Key": api_key, "X-Tenant-ID": tenant_id}


def _register_identity(client: TestClient, agent_id: str = "agent-owned-by-a") -> None:
    response = client.post(
        "/v1/identity/agents",
        json={"agent_id": agent_id},
        headers=_headers("owner-a-key"),
    )
    assert response.status_code == 200, response.text


@pytest.fixture()
def unclassified_route() -> Iterator[str]:
    path = "/v1/unclassified-authorization-probe"
    original_routes = list(app.router.routes)

    async def _probe() -> dict[str, bool]:
        return {"executed": True}

    app.add_api_route(path, _probe, methods=["GET"], include_in_schema=False)
    try:
        yield path
    finally:
        app.router.routes[:] = original_routes


def test_dependency_preserves_typed_authorization_context(authorization_runtime: None) -> None:
    context = require_api_key(
        x_api_key="read-only-key",
        authorization=None,
        x_delegation_token=None,
        x_tenant_id="tenant-a",
    )

    assert isinstance(context, AuthContext)
    assert context == "owner-a"
    assert context.owner == "owner-a"
    assert context.scopes == frozenset({"read"})
    assert context.roles == frozenset({"member"})
    assert context.tenant_id == "tenant-a"
    assert context.auth_method == "api_key"


def test_read_only_principal_cannot_call_write_route(authorization_runtime: None) -> None:
    with TestClient(app) as client:
        response = client.post(
            "/v1/identity/agents",
            json={"agent_id": "read-only-write-attempt"},
            headers=_headers("read-only-key"),
        )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "scope.forbidden"


def test_limited_token_issuer_cannot_mint_broader_scope(authorization_runtime: None) -> None:
    with TestClient(app) as client:
        response = client.post(
            "/v1/auth/tokens",
            json={"scopes": ["write"], "ttl_seconds": 1200},
            headers=_headers("token-issuer-key"),
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "requested scopes exceed issuer authority"


def test_cross_owner_identity_read_is_denied(authorization_runtime: None) -> None:
    with TestClient(app) as client:
        _register_identity(client)
        response = client.get(
            "/v1/identity/agents/agent-owned-by-a",
            headers=_headers("owner-b-key"),
        )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "owner.forbidden"


def test_cross_tenant_request_is_denied(authorization_runtime: None) -> None:
    with TestClient(app) as client:
        response = client.get(
            "/v1/agents",
            headers=_headers("owner-a-key", tenant_id="tenant-b"),
        )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "tenant.forbidden"


def test_malformed_tenant_policy_fails_closed(
    authorization_runtime: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTHUB_OWNER_TENANTS_JSON", "{malformed")
    with TestClient(app) as client:
        response = client.get("/v1/agents", headers=_headers("owner-a-key"))

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "tenant.forbidden"


def test_unclassified_route_is_denied_before_execution(
    authorization_runtime: None,
    unclassified_route: str,
) -> None:
    with TestClient(app) as client:
        response = client.get(unclassified_route, headers=_headers("owner-a-key"))

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "route.unclassified"


def test_every_registered_operation_has_an_explicit_policy(authorization_runtime: None) -> None:
    denied = [row for row in route_policy_map(app.routes) if row["classification"] == "denied"]

    assert denied == []
