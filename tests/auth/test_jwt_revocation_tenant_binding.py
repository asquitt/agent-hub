from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.auth import resolve_auth_context
from src.identity.jwt_tokens import issue_jwt, verify_jwt
from src.identity.oauth_clients import OAUTH_CLIENT_STORE
from src.identity.storage import get_agent_identity_auth_snapshot, reconfigure, reset_for_tests


@pytest.fixture()
def jwt_auth_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identity_db = tmp_path / "identity.db"
    monkeypatch.setenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "enforce")
    monkeypatch.setenv("AGENTHUB_IDENTITY_DB_PATH", str(identity_db))
    monkeypatch.setenv("AGENTHUB_LEASE_DB_PATH", str(tmp_path / "lease.db"))
    monkeypatch.setenv("AGENTHUB_IDENTITY_SIGNING_SECRET", "jwt-revocation-tenant-secret-at-least-32-bytes")
    monkeypatch.setenv("AGENTHUB_AUTH_TOKEN_SECRET", "jwt-revocation-auth-secret-at-least-32-bytes")
    monkeypatch.setenv(
        "AGENTHUB_API_KEYS_JSON",
        json.dumps(
            {
                "owner-a-key": {"owner": "owner-a", "scopes": ["*"], "roles": ["member"]},
                "owner-b-key": {"owner": "owner-b", "scopes": ["*"], "roles": ["member"]},
            }
        ),
    )
    monkeypatch.setenv(
        "AGENTHUB_OWNER_TENANTS_JSON",
        json.dumps(
            {
                "owner-a": ["tenant-a", "tenant-b"],
                "owner-b": ["tenant-a", "tenant-b"],
            }
        ),
    )
    reset_for_tests(identity_db)
    OAUTH_CLIENT_STORE.reset_for_tests(identity_db)


def _api_headers(*, tenant_id: str = "tenant-a", api_key: str = "owner-a-key") -> dict[str, str]:
    return {"X-API-Key": api_key, "X-Tenant-ID": tenant_id}


def _bearer_headers(token: str, *, tenant_id: str = "tenant-a") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "X-Tenant-ID": tenant_id}


def _register_agent(client: TestClient, *, agent_id: str = "agent-a") -> None:
    response = client.post(
        "/v1/identity/agents",
        json={"agent_id": agent_id},
        headers=_api_headers(),
    )
    assert response.status_code == 200, response.text


def _issue_agent_jwt(client: TestClient, *, agent_id: str = "agent-a", tenant_id: str = "tenant-a") -> str:
    response = client.post(
        "/v1/identity/tokens/jwt",
        json={"agent_id": agent_id, "scopes": ["read"]},
        headers=_api_headers(tenant_id=tenant_id),
    )
    assert response.status_code == 200, response.text
    return str(response.json()["token"])


def _assert_agent_request_allowed(client: TestClient, token: str, *, tenant_id: str = "tenant-a") -> None:
    response = client.get("/v1/agents", headers=_bearer_headers(token, tenant_id=tenant_id))
    assert response.status_code == 200, response.text


def _assert_agent_request_denied(client: TestClient, token: str, *, tenant_id: str = "tenant-a") -> None:
    response = client.get("/v1/agents", headers=_bearer_headers(token, tenant_id=tenant_id))
    assert response.status_code == 401, response.text


def test_active_agent_jwt_authenticates_with_signed_tenant(jwt_auth_runtime: None) -> None:
    with TestClient(app) as client:
        _register_agent(client)
        token = _issue_agent_jwt(client)
        _assert_agent_request_allowed(client, token)

    claims = verify_jwt(token)
    assert claims["tenant_id"] == "tenant-a"
    assert claims["identity_generation"]


def test_revoked_agent_jwt_is_denied_on_the_next_request(jwt_auth_runtime: None) -> None:
    with TestClient(app) as client:
        _register_agent(client)
        token = _issue_agent_jwt(client)
        _assert_agent_request_allowed(client, token)

        revoked = client.post(
            "/v1/identity/agents/agent-a/revoke",
            json={"reason": "security_incident"},
            headers=_api_headers(),
        )
        assert revoked.status_code == 200, revoked.text
        _assert_agent_request_denied(client, token)


def test_inactive_agent_jwt_is_denied_on_the_next_request(jwt_auth_runtime: None) -> None:
    with TestClient(app) as client:
        _register_agent(client)
        token = _issue_agent_jwt(client)
        _assert_agent_request_allowed(client, token)

        suspended = client.patch(
            "/v1/identity/agents/agent-a",
            json={"status": "suspended"},
            headers={**_api_headers(), "Idempotency-Key": "suspend-agent-a"},
        )
        assert suspended.status_code == 200, suspended.text
        _assert_agent_request_denied(client, token)


def test_agent_jwt_owner_must_match_current_identity_owner(jwt_auth_runtime: None) -> None:
    with TestClient(app) as client:
        _register_agent(client)
        _, identity_generation = get_agent_identity_auth_snapshot("agent-a")
        assert identity_generation is not None
        token = issue_jwt(
            subject="owner-b",
            agent_id="agent-a",
            tenant_id="tenant-a",
            identity_generation=identity_generation,
            scopes=["read"],
        )["token"]
        _assert_agent_request_denied(client, token)


def test_request_tenant_cannot_override_signed_agent_tenant(jwt_auth_runtime: None) -> None:
    with TestClient(app) as client:
        _register_agent(client)
        token = _issue_agent_jwt(client, tenant_id="tenant-a")
        _assert_agent_request_denied(client, token, tenant_id="tenant-b")


def test_tenantless_legacy_agent_jwt_fails_closed(jwt_auth_runtime: None) -> None:
    with TestClient(app) as client:
        _register_agent(client)
        token = issue_jwt(subject="owner-a", agent_id="agent-a", scopes=["read"])["token"]
        _assert_agent_request_denied(client, token)


@pytest.mark.parametrize("inactive_status", ["revoked", "suspended"])
def test_old_agent_jwt_stays_denied_after_reactivation(
    jwt_auth_runtime: None,
    inactive_status: str,
) -> None:
    with TestClient(app) as client:
        _register_agent(client)
        token = _issue_agent_jwt(client)

        if inactive_status == "revoked":
            transition = client.post(
                "/v1/identity/agents/agent-a/revoke",
                json={"reason": "security_incident"},
                headers=_api_headers(),
            )
        else:
            transition = client.patch(
                "/v1/identity/agents/agent-a",
                json={"status": inactive_status},
                headers={**_api_headers(), "Idempotency-Key": "suspend-before-reactivation"},
            )
        assert transition.status_code == 200, transition.text
        _assert_agent_request_denied(client, token)

        reactivated = client.patch(
            "/v1/identity/agents/agent-a",
            json={"status": "active"},
            headers={**_api_headers(), "Idempotency-Key": f"reactivate-from-{inactive_status}"},
        )
        assert reactivated.status_code == 200, reactivated.text
        reconfigure()
        _assert_agent_request_denied(client, token)

        replacement_token = _issue_agent_jwt(client)
        _assert_agent_request_allowed(client, replacement_token)


def test_registered_oauth_client_jwt_remains_non_agent_auth(jwt_auth_runtime: None) -> None:
    with TestClient(app) as client:
        registered = client.post(
            "/v1/oauth/register",
            json={"client_name": "integration", "scope": "read"},
            headers=_api_headers(),
        )
        assert registered.status_code == 200, registered.text
        client_record = registered.json()

        issued = client.post(
            "/v1/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_record["client_id"],
                "client_secret": client_record["client_secret"],
                "scope": "read",
            },
        )
        assert issued.status_code == 200, issued.text
        token = str(issued.json()["access_token"])

        context = resolve_auth_context(
            authorization=f"Bearer {token}",
            tenant_id="tenant-default",
        )

    assert context is not None
    assert context.owner == client_record["client_id"]
    assert context.agent_id == client_record["client_id"]
    assert context.tenant_id == "tenant-default"
