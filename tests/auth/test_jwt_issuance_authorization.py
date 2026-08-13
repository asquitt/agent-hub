from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.identity.constants import CREDENTIAL_TYPE_API_KEY
from src.identity.credentials import issue_credential
from src.identity.jwt_tokens import verify_jwt
from src.identity.storage import register_agent_identity, reset_for_tests


@pytest.fixture()
def jwt_issuance_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    monkeypatch.setenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "enforce")
    monkeypatch.setenv("AGENTHUB_AUTH_TOKEN_SECRET", "jwt-issuance-auth-secret")
    monkeypatch.setenv(
        "AGENTHUB_IDENTITY_SIGNING_SECRET",
        "jwt-issuance-identity-secret-at-least-32-bytes",
    )
    monkeypatch.setenv(
        "AGENTHUB_API_KEYS_JSON",
        json.dumps(
            {
                "owner-a-key": {
                    "owner": "owner-a",
                    "scopes": ["identity.write", "runtime.read"],
                    "roles": ["member"],
                },
                "owner-b-key": {
                    "owner": "owner-b",
                    "scopes": ["identity.write", "runtime.read"],
                    "roles": ["member"],
                },
                "platform-admin-key": {
                    "owner": "owner-platform",
                    "scopes": ["identity.write"],
                    "roles": ["admin"],
                },
                "platform-member-key": {
                    "owner": "owner-platform",
                    "scopes": ["identity.write"],
                    "roles": ["member"],
                },
            }
        ),
    )
    monkeypatch.setenv(
        "AGENTHUB_OWNER_TENANTS_JSON",
        json.dumps(
            {
                "owner-a": ["tenant-a"],
                "owner-b": ["tenant-a"],
                "owner-platform": ["tenant-a"],
            }
        ),
    )
    identity_db = tmp_path / "identity.db"
    monkeypatch.setenv("AGENTHUB_IDENTITY_DB_PATH", str(identity_db))
    reset_for_tests(identity_db)

    for agent_id, owner in (
        ("agent-a", "owner-a"),
        ("agent-a-sibling", "owner-a"),
        ("agent-b", "owner-b"),
        ("agent-platform", "owner-platform"),
    ):
        register_agent_identity(
            agent_id=agent_id,
            owner=owner,
            credential_type=CREDENTIAL_TYPE_API_KEY,
        )

    credential = issue_credential(
        agent_id="agent-a",
        scopes=["identity.write", "runtime.read"],
        owner="owner-a",
    )
    return {"agent_a_secret": credential["secret"]}


def _api_key_headers(api_key: str, tenant_id: str = "tenant-a") -> dict[str, str]:
    return {"X-API-Key": api_key, "X-Tenant-ID": tenant_id}


def _issue(client: TestClient, *, agent_id: str, scopes: list[str], headers: dict[str, str]):
    return client.post(
        "/v1/identity/tokens/jwt",
        json={"agent_id": agent_id, "scopes": scopes},
        headers=headers,
    )


def test_valid_owner_can_issue_attenuated_jwt(jwt_issuance_runtime: dict[str, str]) -> None:
    with TestClient(app) as client:
        response = _issue(
            client,
            agent_id="agent-a",
            scopes=["runtime.read"],
            headers=_api_key_headers("owner-a-key"),
        )

    assert response.status_code == 200, response.text
    claims = verify_jwt(response.json()["token"])
    assert claims["sub"] == "owner-a"
    assert claims["agent_id"] == "agent-a"
    assert claims["scopes"] == ["runtime.read"]


def test_cross_owner_agent_is_denied(jwt_issuance_runtime: dict[str, str]) -> None:
    with TestClient(app) as client:
        response = _issue(
            client,
            agent_id="agent-b",
            scopes=["runtime.read"],
            headers=_api_key_headers("owner-a-key"),
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "agent identity belongs to another owner"


def test_scope_escalation_is_denied(jwt_issuance_runtime: dict[str, str]) -> None:
    with TestClient(app) as client:
        response = _issue(
            client,
            agent_id="agent-a",
            scopes=["runtime.write"],
            headers=_api_key_headers("owner-a-key"),
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "requested scopes exceed issuer authority"


def test_agent_principal_can_issue_only_for_itself(jwt_issuance_runtime: dict[str, str]) -> None:
    headers = {
        "Authorization": f"AgentCredential {jwt_issuance_runtime['agent_a_secret']}",
        "X-Tenant-ID": "tenant-a",
    }
    with TestClient(app) as client:
        self_response = _issue(
            client,
            agent_id="agent-a",
            scopes=["runtime.read"],
            headers=headers,
        )
        sibling_response = _issue(
            client,
            agent_id="agent-a-sibling",
            scopes=["runtime.read"],
            headers=headers,
        )

    assert self_response.status_code == 200, self_response.text
    assert sibling_response.status_code == 403
    assert sibling_response.json()["detail"] == "agent principal cannot issue a token for another agent"


def test_tenant_mismatch_is_denied(jwt_issuance_runtime: dict[str, str]) -> None:
    with TestClient(app) as client:
        response = _issue(
            client,
            agent_id="agent-a",
            scopes=["runtime.read"],
            headers=_api_key_headers("owner-a-key", tenant_id="tenant-b"),
        )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "tenant.forbidden"


def test_only_explicit_platform_admin_role_bypasses_scope_attenuation(
    jwt_issuance_runtime: dict[str, str],
) -> None:
    with TestClient(app) as client:
        member_response = _issue(
            client,
            agent_id="agent-platform",
            scopes=["runtime.admin"],
            headers=_api_key_headers("platform-member-key"),
        )
        admin_response = _issue(
            client,
            agent_id="agent-platform",
            scopes=["runtime.admin"],
            headers=_api_key_headers("platform-admin-key"),
        )

    assert member_response.status_code == 403
    assert admin_response.status_code == 200, admin_response.text
