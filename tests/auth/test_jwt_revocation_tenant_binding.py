from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.auth import AuthContext, issue_scoped_token, resolve_auth_context
from src.identity.credentials import issue_credential
from src.identity import delegation_tokens
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


def _verify_jwt_endpoint(client: TestClient, token: str, *, tenant_id: str = "tenant-a") -> dict[str, object]:
    response = client.post(
        "/v1/identity/tokens/jwt/verify",
        json={"token": token},
        headers=_api_headers(tenant_id=tenant_id),
    )
    assert response.status_code == 200, response.text
    return response.json()


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
        _, identity_generation, _ = get_agent_identity_auth_snapshot("agent-a")
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


def test_agent_jwt_issuance_must_match_persisted_identity_tenant(jwt_auth_runtime: None) -> None:
    with TestClient(app) as client:
        _register_agent(client)
        response = client.post(
            "/v1/identity/tokens/jwt",
            json={"agent_id": "agent-a", "scopes": ["read"]},
            headers=_api_headers(tenant_id="tenant-b"),
        )

    assert response.status_code == 403, response.text


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


def _register_oauth_client(client: TestClient) -> dict[str, object]:
    registered = client.post(
        "/v1/oauth/register",
        json={"client_name": "integration", "scope": "read"},
        headers=_api_headers(),
    )
    assert registered.status_code == 200, registered.text
    return registered.json()


def _issue_oauth_token(client: TestClient, client_record: dict[str, object]) -> str:
    issued = client.post(
        "/v1/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": str(client_record["client_id"]),
            "client_secret": str(client_record["client_secret"]),
            "scope": "read",
        },
    )
    assert issued.status_code == 200, issued.text
    return str(issued.json()["access_token"])


def test_registered_oauth_client_jwt_uses_registrar_owner_and_tenant(jwt_auth_runtime: None) -> None:
    with TestClient(app) as client:
        client_record = _register_oauth_client(client)
        token = _issue_oauth_token(client, client_record)

        context = resolve_auth_context(
            authorization=f"Bearer {token}",
            tenant_id="tenant-a",
        )

    claims = verify_jwt(token, issuer="urn:agenthub:registry")
    assert claims["sub"] == "owner-a"
    assert claims["agent_id"] == client_record["client_id"]
    assert claims["tenant_id"] == "tenant-a"
    assert context is not None
    assert context.owner == "owner-a"
    assert context.agent_id == client_record["client_id"]
    assert context.tenant_id == "tenant-a"


def test_request_tenant_cannot_override_signed_oauth_tenant(jwt_auth_runtime: None) -> None:
    with TestClient(app) as client:
        client_record = _register_oauth_client(client)
        token = _issue_oauth_token(client, client_record)

        _assert_agent_request_denied(client, token, tenant_id="tenant-b")


@pytest.mark.parametrize(
    ("subject", "tenant_id"),
    [("owner-b", "tenant-a"), ("owner-a", "tenant-b")],
)
def test_oauth_jwt_claims_must_match_durable_client_owner_and_tenant(
    jwt_auth_runtime: None,
    subject: str,
    tenant_id: str,
) -> None:
    with TestClient(app) as client:
        client_record = _register_oauth_client(client)
        token = issue_jwt(
            subject=subject,
            agent_id=str(client_record["client_id"]),
            tenant_id=tenant_id,
            scopes=["read"],
            issuer="urn:agenthub:registry",
        )["token"]

        _assert_agent_request_denied(client, token, tenant_id=tenant_id)


def test_tenantless_legacy_oauth_jwt_fails_closed(jwt_auth_runtime: None) -> None:
    with TestClient(app) as client:
        client_record = _register_oauth_client(client)
        token = issue_jwt(
            subject="owner-a",
            agent_id=str(client_record["client_id"]),
            scopes=["read"],
            issuer="urn:agenthub:registry",
        )["token"]

        _assert_agent_request_denied(client, token)


def test_delegation_token_cannot_replay_across_tenants(
    jwt_auth_runtime: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with TestClient(app) as client:
        _register_agent(client)

    monkeypatch.setattr(
        delegation_tokens,
        "verify_delegation_token",
        lambda _token: {
            "token_id": "delegation-a",
            "subject_agent_id": "agent-a",
            "delegated_scopes": ["read"],
            "owner": "owner-a",
            "tenant_id": "tenant-a",
        },
    )
    allowed = resolve_auth_context(x_delegation_token="delegation-token", tenant_id="tenant-a")
    assert allowed is not None
    assert allowed.owner == "owner-a"
    assert allowed.tenant_id == "tenant-a"

    with pytest.raises(HTTPException, match="delegation token auth failed"):
        resolve_auth_context(x_delegation_token="delegation-token", tenant_id="tenant-b")


def test_delegation_token_owner_must_match_live_identity(
    jwt_auth_runtime: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with TestClient(app) as client:
        _register_agent(client)

    monkeypatch.setattr(
        delegation_tokens,
        "verify_delegation_token",
        lambda _token: {
            "token_id": "delegation-wrong-owner",
            "subject_agent_id": "agent-a",
            "delegated_scopes": ["read"],
            "owner": "owner-b",
            "tenant_id": "tenant-a",
        },
    )

    with pytest.raises(HTTPException, match="delegation token auth failed"):
        resolve_auth_context(x_delegation_token="delegation-token", tenant_id="tenant-a")


def test_agent_credential_cannot_replay_across_tenants(jwt_auth_runtime: None) -> None:
    with TestClient(app) as client:
        _register_agent(client)

    credential = issue_credential(agent_id="agent-a", scopes=["read"], owner="owner-a")
    authorization = f"AgentCredential {credential['secret']}"
    allowed = resolve_auth_context(authorization=authorization, tenant_id="tenant-a")
    assert allowed is not None
    assert allowed.owner == "owner-a"
    assert allowed.tenant_id == "tenant-a"

    with pytest.raises(HTTPException, match="agent credential auth failed"):
        resolve_auth_context(authorization=authorization, tenant_id="tenant-b")


def test_scoped_bearer_token_cannot_replay_across_tenants(jwt_auth_runtime: None) -> None:
    issuer = AuthContext(
        "owner-a",
        scopes=["read"],
        roles=["member"],
        tenant_id="tenant-a",
        auth_method="api_key",
    )
    token = str(issue_scoped_token(issuer, ["read"])["access_token"])
    allowed = resolve_auth_context(authorization=f"Bearer {token}", tenant_id="tenant-a")
    assert allowed is not None
    assert allowed.tenant_id == "tenant-a"

    with pytest.raises(HTTPException, match="bearer token tenant mismatch"):
        resolve_auth_context(authorization=f"Bearer {token}", tenant_id="tenant-b")


def test_tenantless_legacy_scoped_bearer_token_fails_closed(jwt_auth_runtime: None) -> None:
    payload = {"sub": "owner-a", "scopes": ["read"], "roles": ["member"], "exp": 4_102_444_800}
    body = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("utf-8").rstrip("=")
    signature = hmac.new(
        b"jwt-revocation-auth-secret-at-least-32-bytes",
        body.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    with pytest.raises(HTTPException, match="bearer token missing tenant_id claim"):
        resolve_auth_context(authorization=f"Bearer {body}.{signature}", tenant_id="tenant-a")


def test_jwt_verify_endpoint_rejects_revoked_agent(jwt_auth_runtime: None) -> None:
    with TestClient(app) as client:
        _register_agent(client)
        token = _issue_agent_jwt(client)
        assert _verify_jwt_endpoint(client, token)["valid"] is True

        revoked = client.post(
            "/v1/identity/agents/agent-a/revoke",
            json={"reason": "verification-revocation"},
            headers=_api_headers(),
        )
        assert revoked.status_code == 200, revoked.text
        verification = _verify_jwt_endpoint(client, token)

    assert verification["valid"] is False


def test_jwt_verify_endpoint_rejects_old_token_after_suspension_and_reactivation(
    jwt_auth_runtime: None,
) -> None:
    with TestClient(app) as client:
        _register_agent(client)
        token = _issue_agent_jwt(client)

        suspended = client.patch(
            "/v1/identity/agents/agent-a",
            json={"status": "suspended"},
            headers={**_api_headers(), "Idempotency-Key": "verify-suspend"},
        )
        assert suspended.status_code == 200, suspended.text
        assert _verify_jwt_endpoint(client, token)["valid"] is False

        reactivated = client.patch(
            "/v1/identity/agents/agent-a",
            json={"status": "active"},
            headers={**_api_headers(), "Idempotency-Key": "verify-reactivate"},
        )
        assert reactivated.status_code == 200, reactivated.text
        reconfigure()
        verification = _verify_jwt_endpoint(client, token)

    assert verification["valid"] is False


@pytest.mark.parametrize(
    ("subject", "token_tenant_id", "request_tenant_id"),
    [("owner-b", "tenant-a", "tenant-a"), ("owner-a", "tenant-b", "tenant-b")],
)
def test_jwt_verify_endpoint_rejects_agent_owner_or_tenant_mismatch(
    jwt_auth_runtime: None,
    subject: str,
    token_tenant_id: str,
    request_tenant_id: str,
) -> None:
    with TestClient(app) as client:
        _register_agent(client)
        _, generation, _ = get_agent_identity_auth_snapshot("agent-a")
        assert generation is not None
        token = issue_jwt(
            subject=subject,
            agent_id="agent-a",
            tenant_id=token_tenant_id,
            identity_generation=generation,
            scopes=["read"],
        )["token"]
        verification = _verify_jwt_endpoint(client, token, tenant_id=request_tenant_id)

    assert verification["valid"] is False


def test_jwt_verify_endpoint_accepts_live_oauth_client(jwt_auth_runtime: None) -> None:
    with TestClient(app) as client:
        client_record = _register_oauth_client(client)
        token = _issue_oauth_token(client, client_record)
        verification = _verify_jwt_endpoint(client, token)

    assert verification["valid"] is True
    claims = verification["claims"]
    assert isinstance(claims, dict)
    assert claims["sub"] == "owner-a"
    assert claims["tenant_id"] == "tenant-a"
