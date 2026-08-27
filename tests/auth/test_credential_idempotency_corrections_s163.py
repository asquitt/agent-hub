from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.billing import service as billing_service
from src.identity.constants import CREDENTIAL_TYPE_API_KEY, CRED_STATUS_ACTIVE
from src.identity.credentials import issue_credential
from src.identity.jwt_tokens import TOKEN_USE_AGENT, issue_jwt
from src.identity.storage import (
    IDENTITY_STORAGE,
    get_agent_identity_auth_snapshot,
    register_agent_identity,
    reset_for_tests,
)


@pytest.fixture()
def correction_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identity_db = tmp_path / "identity.db"
    billing_db = tmp_path / "billing.db"
    monkeypatch.setenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "enforce")
    monkeypatch.setenv("AGENTHUB_IDENTITY_DB_PATH", str(identity_db))
    monkeypatch.setenv("AGENTHUB_BILLING_DB_PATH", str(billing_db))
    monkeypatch.setenv("AGENTHUB_COST_DB_PATH", str(billing_db))
    monkeypatch.setenv("AGENTHUB_IDENTITY_SIGNING_SECRET", "credential-correction-signing-secret-at-least-32-bytes")
    monkeypatch.setenv("AGENTHUB_AUTH_TOKEN_SECRET", "credential-correction-auth-secret-at-least-32-bytes")
    monkeypatch.setenv(
        "AGENTHUB_API_KEYS_JSON",
        json.dumps(
            {
                "owner-a-key": {
                    "owner": "owner-a",
                    "scopes": ["identity.write", "billing.write"],
                    "roles": ["member"],
                },
                "owner-b-key": {
                    "owner": "owner-b",
                    "scopes": ["identity.write", "billing.write"],
                    "roles": ["member"],
                },
            }
        ),
    )
    monkeypatch.setenv(
        "AGENTHUB_OWNER_TENANTS_JSON",
        json.dumps({"owner-a": ["tenant-shared"], "owner-b": ["tenant-shared"]}),
    )
    reset_for_tests(identity_db)
    billing_service.reset_for_tests(db_path=billing_db)
    for agent_id, owner in (("agent-a", "owner-a"), ("agent-b", "owner-b")):
        register_agent_identity(
            agent_id=agent_id,
            owner=owner,
            tenant_id="tenant-shared",
            credential_type=CREDENTIAL_TYPE_API_KEY,
        )


def _api_headers(api_key: str, idempotency_key: str) -> dict[str, str]:
    return {
        "X-API-Key": api_key,
        "X-Tenant-ID": "tenant-shared",
        "Idempotency-Key": idempotency_key,
    }


def _agent_jwt(*, agent_id: str, owner: str) -> str:
    _, generation, tenant_id = get_agent_identity_auth_snapshot(agent_id)
    assert generation is not None
    assert tenant_id == "tenant-shared"
    return str(
        issue_jwt(
            subject=owner,
            agent_id=agent_id,
            tenant_id=tenant_id,
            identity_generation=generation,
            token_use=TOKEN_USE_AGENT,
            scopes=["billing.write"],
        )["token"]
    )


def test_credential_issue_and_rotation_cannot_exceed_actor_scopes(correction_runtime: None) -> None:
    inherited_wildcard = issue_credential(agent_id="agent-a", scopes=["*"], owner="owner-a")

    with TestClient(app) as client:
        amplified_issue = client.post(
            "/v1/identity/agents/agent-a/credentials",
            json={"scopes": ["*"]},
            headers=_api_headers("owner-a-key", "reject-wildcard-issue"),
        )
        valid_issue = client.post(
            "/v1/identity/agents/agent-a/credentials",
            json={"scopes": ["billing.write"]},
            headers=_api_headers("owner-a-key", "valid-attenuated-issue"),
        )
        assert valid_issue.status_code == 200, valid_issue.text
        valid_credential_id = str(valid_issue.json()["credential_id"])

        amplified_rotation = client.post(
            f"/v1/identity/credentials/{valid_credential_id}/rotate",
            json={"new_scopes": ["runtime.write"]},
            headers=_api_headers("owner-a-key", "reject-unrelated-rotation"),
        )
        inherited_rotation = client.post(
            f"/v1/identity/credentials/{inherited_wildcard['credential_id']}/rotate",
            json={},
            headers=_api_headers("owner-a-key", "reject-inherited-wildcard"),
        )
        valid_rotation = client.post(
            f"/v1/identity/credentials/{valid_credential_id}/rotate",
            json={"new_scopes": ["billing.write"]},
            headers=_api_headers("owner-a-key", "valid-attenuated-rotation"),
        )

    assert amplified_issue.status_code == 403
    assert amplified_issue.json()["detail"] == "requested scopes exceed issuer authority"
    assert amplified_rotation.status_code == 403
    assert amplified_rotation.json()["detail"] == "requested scopes exceed issuer authority"
    assert inherited_rotation.status_code == 403
    assert inherited_rotation.json()["detail"] == "requested scopes exceed issuer authority"
    assert IDENTITY_STORAGE.get_credential(inherited_wildcard["credential_id"])["status"] == CRED_STATUS_ACTIVE
    assert valid_rotation.status_code == 200, valid_rotation.text
    assert valid_rotation.json()["scopes"] == ["billing.write"]


def test_idempotency_replay_is_namespaced_by_full_authenticated_principal(correction_runtime: None) -> None:
    token_a = _agent_jwt(agent_id="agent-a", owner="owner-a")
    token_b = _agent_jwt(agent_id="agent-b", owner="owner-b")
    body = {
        "account_id": "acct-shared",
        "plan_id": "standard",
        "monthly_fee_usd": 25.0,
        "included_units": 100,
    }
    base_headers = {"X-Tenant-ID": "tenant-shared", "Idempotency-Key": "same-principal-key"}

    with TestClient(app) as client:
        first = client.post(
            "/v1/billing/subscriptions",
            json=body,
            headers={**base_headers, "Authorization": f"Bearer {token_a}"},
        )
        second = client.post(
            "/v1/billing/subscriptions",
            json=body,
            headers={**base_headers, "Authorization": f"Bearer {token_b}"},
        )
        unauthenticated = client.post(
            "/v1/billing/subscriptions",
            json=body,
            headers=base_headers,
        )

    assert first.status_code == 200, first.text
    assert first.json()["owner"] == "owner-a"
    assert second.status_code == 200, second.text
    assert second.json()["owner"] == "owner-b"
    assert second.headers.get("X-AgentHub-Idempotent-Replay") is None
    assert unauthenticated.status_code == 401
    assert unauthenticated.headers.get("X-AgentHub-Idempotent-Replay") is None
