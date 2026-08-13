from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.auth import AuthContext
from src.identity import storage as identity_storage
from src.identity.credentials import get_credential_metadata, issue_credential, revoke_credential
from src.runtime.secret_vault import (
    get_secret,
    list_secrets,
    reset_for_tests as reset_vault_for_tests,
    revoke_secret,
    store_secret,
)


@pytest.fixture()
def resource_auth_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "enforce")
    monkeypatch.setenv(
        "AGENTHUB_API_KEYS_JSON",
        json.dumps(
            {
                "owner-a-key": {"owner": "owner-a", "scopes": ["*"], "roles": ["admin"]},
                "owner-b-key": {"owner": "owner-b", "scopes": ["*"], "roles": ["admin"]},
            }
        ),
    )
    monkeypatch.setenv(
        "AGENTHUB_OWNER_TENANTS_JSON",
        json.dumps({"owner-a": ["tenant-a", "tenant-b"], "owner-b": ["tenant-a"]}),
    )
    monkeypatch.setenv("AGENTHUB_IDENTITY_SIGNING_SECRET", "object-auth-identity-secret")
    monkeypatch.setenv("AGENTHUB_VAULT_KEY", "object-auth-vault-secret")
    identity_db = tmp_path / "identity.db"
    monkeypatch.setenv("AGENTHUB_IDENTITY_DB_PATH", str(identity_db))
    identity_storage.reset_for_tests(db_path=identity_db)
    reset_vault_for_tests()


def _headers(api_key: str, tenant_id: str = "tenant-a") -> dict[str, str]:
    return {"X-API-Key": api_key, "X-Tenant-ID": tenant_id}


def _agent_headers(secret: str, tenant_id: str = "tenant-a") -> dict[str, str]:
    return {"Authorization": f"AgentCredential {secret}", "X-Tenant-ID": tenant_id}


def _register(
    client: TestClient,
    agent_id: str,
    *,
    api_key: str = "owner-a-key",
    tenant_id: str = "tenant-a",
) -> dict[str, object]:
    response = client.post(
        "/v1/identity/agents",
        json={"agent_id": agent_id},
        headers=_headers(api_key, tenant_id),
    )
    assert response.status_code == 200, response.text
    return response.json()


def _issue(
    client: TestClient,
    agent_id: str,
    *,
    api_key: str = "owner-a-key",
    tenant_id: str = "tenant-a",
) -> dict[str, object]:
    response = client.post(
        f"/v1/identity/agents/{agent_id}/credentials",
        json={"scopes": ["*"], "ttl_seconds": 3600},
        headers=_headers(api_key, tenant_id),
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_identity_read_and_credential_lifecycle_are_owner_scoped(
    resource_auth_runtime: None,
) -> None:
    with TestClient(app) as client:
        _register(client, "owner-a-agent")

        same_owner = client.get(
            "/v1/identity/agents/owner-a-agent",
            headers=_headers("owner-a-key"),
        )
        cross_owner = client.get(
            "/v1/identity/agents/owner-a-agent",
            headers=_headers("owner-b-key"),
        )
        denied_issue = client.post(
            "/v1/identity/agents/owner-a-agent/credentials",
            json={"scopes": ["read"], "ttl_seconds": 3600},
            headers=_headers("owner-b-key"),
        )
        credential = _issue(client, "owner-a-agent")
        denied_revoke = client.post(
            f"/v1/identity/credentials/{credential['credential_id']}/revoke",
            json={"reason": "cross-owner-attempt"},
            headers=_headers("owner-b-key"),
        )
        allowed_revoke = client.post(
            f"/v1/identity/credentials/{credential['credential_id']}/revoke",
            json={"reason": "owner-request"},
            headers=_headers("owner-a-key"),
        )

    assert same_owner.status_code == 200
    assert cross_owner.status_code == 403
    assert denied_issue.status_code == 403
    assert denied_revoke.status_code == 403
    assert allowed_revoke.status_code == 200
    assert allowed_revoke.json()["status"] == "revoked"


def test_identity_and_credentials_are_isolated_between_same_owner_tenants(
    resource_auth_runtime: None,
) -> None:
    with TestClient(app) as client:
        _register(client, "tenant-a-agent", tenant_id="tenant-a")
        credential = _issue(client, "tenant-a-agent", tenant_id="tenant-a")

        identity_read = client.get(
            "/v1/identity/agents/tenant-a-agent",
            headers=_headers("owner-a-key", "tenant-b"),
        )
        credential_read = client.get(
            f"/v1/identity/credentials/{credential['credential_id']}",
            headers=_headers("owner-a-key", "tenant-b"),
        )
        credential_revoke = client.post(
            f"/v1/identity/credentials/{credential['credential_id']}/revoke",
            json={"reason": "wrong-tenant"},
            headers=_headers("owner-a-key", "tenant-b"),
        )

    assert identity_read.status_code == 404
    assert credential_read.status_code == 404
    assert credential_revoke.status_code == 404


def test_vault_store_get_list_and_revoke_are_owner_and_tenant_scoped(
    resource_auth_runtime: None,
) -> None:
    with TestClient(app) as client:
        stored = client.post(
            "/v1/vault/secrets",
            json={"name": "owner-a-secret", "value": "sensitive"},
            headers=_headers("owner-a-key", "tenant-a"),
        )
        assert stored.status_code == 200, stored.text
        secret_id = stored.json()["secret_id"]

        same_owner = client.get(
            f"/v1/vault/secrets/{secret_id}",
            headers=_headers("owner-a-key", "tenant-a"),
        )
        cross_owner = client.get(
            f"/v1/vault/secrets/{secret_id}",
            headers=_headers("owner-b-key", "tenant-a"),
        )
        cross_tenant = client.get(
            f"/v1/vault/secrets/{secret_id}",
            headers=_headers("owner-a-key", "tenant-b"),
        )
        cross_owner_list = client.get(
            "/v1/vault/secrets",
            headers=_headers("owner-b-key", "tenant-a"),
        )
        cross_tenant_list = client.get(
            "/v1/vault/secrets",
            headers=_headers("owner-a-key", "tenant-b"),
        )
        denied_revoke = client.post(
            f"/v1/vault/secrets/{secret_id}/revoke",
            headers=_headers("owner-b-key", "tenant-a"),
        )
        allowed_revoke = client.post(
            f"/v1/vault/secrets/{secret_id}/revoke",
            headers=_headers("owner-a-key", "tenant-a"),
        )

    assert same_owner.status_code == 200
    assert cross_owner.status_code == 404
    assert cross_tenant.status_code == 404
    assert cross_owner_list.json() == {"total": 0, "secrets": []}
    assert cross_tenant_list.json() == {"total": 0, "secrets": []}
    assert denied_revoke.status_code == 404
    assert allowed_revoke.status_code == 200
    assert allowed_revoke.json()["status"] == "expired"


def test_agent_bound_context_can_only_use_its_own_identity_and_vault_objects(
    resource_auth_runtime: None,
) -> None:
    with TestClient(app) as client:
        _register(client, "agent-one")
        _register(client, "agent-two")
        agent_one_credential = _issue(client, "agent-one")

        own_secret_response = client.post(
            "/v1/vault/secrets",
            json={"name": "one", "value": "one", "agent_id": "agent-one"},
            headers=_headers("owner-a-key"),
        )
        other_secret_response = client.post(
            "/v1/vault/secrets",
            json={"name": "two", "value": "two", "agent_id": "agent-two"},
            headers=_headers("owner-a-key"),
        )
        assert own_secret_response.status_code == 200, own_secret_response.text
        assert other_secret_response.status_code == 200, other_secret_response.text
        own_secret = own_secret_response.json()["secret_id"]
        other_secret = other_secret_response.json()["secret_id"]
        agent_headers = _agent_headers(str(agent_one_credential["secret"]))

        own_identity = client.get("/v1/identity/agents/agent-one", headers=agent_headers)
        other_identity = client.get("/v1/identity/agents/agent-two", headers=agent_headers)

    assert own_identity.status_code == 200
    assert other_identity.status_code == 403

    agent_actor = AuthContext(
        "owner-a",
        scopes=("*",),
        roles=("member",),
        tenant_id="tenant-a",
        auth_method="agent_credential",
        agent_id="agent-one",
    )
    assert get_secret(own_secret, actor=agent_actor)["agent_id"] == "agent-one"
    with pytest.raises(KeyError):
        get_secret(other_secret, actor=agent_actor)
    with pytest.raises(PermissionError, match="cannot bind a secret to another agent"):
        store_secret(
            actor=agent_actor,
            name="impersonated",
            value="x",
            agent_id="agent-two",
        )


def test_direct_services_enforce_context_without_http_middleware(
    resource_auth_runtime: None,
) -> None:
    owner_a = AuthContext(
        "owner-a",
        scopes=("*",),
        roles=("member",),
        tenant_id="tenant-a",
        auth_method="api_key",
    )
    owner_b = AuthContext(
        "owner-b",
        scopes=("*",),
        roles=("member",),
        tenant_id="tenant-a",
        auth_method="api_key",
    )
    owner_a_other_tenant = owner_a.with_tenant("tenant-b")

    identity_storage.register_agent_identity_for_actor(
        actor=owner_a,
        agent_id="direct-agent",
        credential_type="api_key",
    )
    credential = issue_credential(
        agent_id="direct-agent",
        scopes=["read"],
        ttl_seconds=3600,
        owner=owner_a,
    )
    secret = store_secret(actor=owner_a, name="direct-secret", value="sensitive")

    assert identity_storage.get_agent_identity_for_actor("direct-agent", owner_a)["owner"] == "owner-a"
    assert get_credential_metadata(credential["credential_id"], actor=owner_a)["agent_id"] == "direct-agent"
    assert get_secret(secret["secret_id"], actor=owner_a)["name"] == "direct-secret"

    for denied_actor in (owner_b, owner_a_other_tenant):
        with pytest.raises(KeyError):
            identity_storage.get_agent_identity_for_actor("direct-agent", denied_actor)
        with pytest.raises(KeyError):
            issue_credential(
                agent_id="direct-agent",
                scopes=["write"],
                ttl_seconds=3600,
                owner=denied_actor,
            )
        with pytest.raises(KeyError):
            get_credential_metadata(credential["credential_id"], actor=denied_actor)
        with pytest.raises(KeyError):
            revoke_credential(
                credential_id=credential["credential_id"],
                owner=denied_actor,
                reason="unauthorized",
            )
        with pytest.raises(KeyError):
            get_secret(secret["secret_id"], actor=denied_actor)
        with pytest.raises(KeyError):
            revoke_secret(secret["secret_id"], actor=denied_actor)
        assert list_secrets(actor=denied_actor) == []

    assert get_credential_metadata(credential["credential_id"], actor=owner_a)["status"] == "active"
    assert get_secret(secret["secret_id"], actor=owner_a)["status"] == "active"


def test_protected_service_paths_reject_plain_owner_strings(
    resource_auth_runtime: None,
) -> None:
    with pytest.raises(PermissionError, match="typed authentication context required"):
        identity_storage.get_agent_identity_for_actor("missing", "owner-a")  # type: ignore[arg-type]
    with pytest.raises(PermissionError, match="typed authentication context required"):
        store_secret(actor="owner-a", name="unsafe", value="unsafe")  # type: ignore[arg-type]
