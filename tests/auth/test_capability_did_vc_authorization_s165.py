from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.identity import storage as identity_storage
from src.identity.did import reset_for_tests as reset_did_for_tests


CAPABILITY_AUDIENCE = "agenthub://runtime-worker"
CAPABILITY_RESOURCE = "urn:agenthub:resource:invoice-ledger"


@pytest.fixture()
def capability_authority_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    monkeypatch.setenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "enforce")
    monkeypatch.setenv(
        "AGENTHUB_API_KEYS_JSON",
        json.dumps(
            {
                "owner-a-key": {
                    "owner": "owner-a",
                    "scopes": ["*"],
                    "roles": ["admin"],
                },
                "owner-b-key": {
                    "owner": "owner-b",
                    "scopes": ["*"],
                    "roles": ["admin"],
                },
            }
        ),
    )
    monkeypatch.setenv(
        "AGENTHUB_OWNER_TENANTS_JSON",
        json.dumps({"owner-a": ["tenant-a", "tenant-b"], "owner-b": ["tenant-a"]}),
    )
    monkeypatch.setenv(
        "AGENTHUB_IDENTITY_SIGNING_SECRET", "s165-capability-authority-secret"
    )
    identity_db = tmp_path / "identity.db"
    monkeypatch.setenv("AGENTHUB_IDENTITY_DB_PATH", str(identity_db))
    identity_storage.reset_for_tests(db_path=identity_db)
    reset_did_for_tests()
    yield
    reset_did_for_tests()


def _headers(
    api_key: str = "owner-a-key", tenant_id: str = "tenant-a"
) -> dict[str, str]:
    return {"X-API-Key": api_key, "X-Tenant-ID": tenant_id}


def _agent_headers(secret: str, tenant_id: str = "tenant-a") -> dict[str, str]:
    return {"Authorization": f"AgentCredential {secret}", "X-Tenant-ID": tenant_id}


def _register(
    client: TestClient,
    agent_id: str,
    *,
    api_key: str = "owner-a-key",
    tenant_id: str = "tenant-a",
) -> None:
    response = client.post(
        "/v1/identity/agents",
        json={"agent_id": agent_id},
        headers=_headers(api_key, tenant_id),
    )
    assert response.status_code == 200, response.text


def _issue_agent_credential(client: TestClient, agent_id: str) -> str:
    response = client.post(
        f"/v1/identity/agents/{agent_id}/credentials",
        json={"scopes": ["*"], "ttl_seconds": 3600},
        headers=_headers(),
    )
    assert response.status_code == 200, response.text
    return str(response.json()["secret"])


def _capability_payload(
    issuer_agent_id: str,
    subject_agent_id: str,
    *,
    caveats: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "issuer_agent_id": issuer_agent_id,
        "subject_agent_id": subject_agent_id,
        "scopes": ["invoices.read"],
        "ttl_seconds": 3600,
        "audience": CAPABILITY_AUDIENCE,
        "resource": CAPABILITY_RESOURCE,
    }
    if caveats is not None:
        payload["caveats"] = caveats
    return payload


def _issue_capability(
    client: TestClient,
    issuer_agent_id: str,
    subject_agent_id: str,
    *,
    headers: dict[str, str] | None = None,
    caveats: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    response = client.post(
        "/v1/identity/capability-tokens/issue",
        json=_capability_payload(issuer_agent_id, subject_agent_id, caveats=caveats),
        headers=headers or _headers(),
    )
    assert response.status_code == 200, response.text
    token = response.json()
    assert token["authority"]["audience"] == CAPABILITY_AUDIENCE
    assert token["authority"]["resource"] == CAPABILITY_RESOURCE
    return token


def _create_did(
    client: TestClient,
    agent_id: str,
    *,
    api_key: str = "owner-a-key",
    tenant_id: str = "tenant-a",
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    response = client.post(
        "/v1/identity/dids",
        json={"agent_id": agent_id},
        headers=headers or _headers(api_key, tenant_id),
    )
    assert response.status_code == 200, response.text
    return response.json()


def _did_suffix(did: str) -> str:
    return did.removeprefix("did:agenthub:")


def _vc_suffix(vc_id: str) -> str:
    return vc_id.removeprefix("urn:uuid:")


def _issue_vc(
    client: TestClient,
    issuer_did: str,
    subject_did: str,
    *,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    response = client.post(
        "/v1/identity/vcs/issue",
        json={
            "issuer_did": issuer_did,
            "subject_did": subject_did,
            "credential_type": "AgentIdentityCredential",
            "claims": {"role": "worker"},
            "ttl_seconds": 3600,
        },
        headers=headers or _headers(),
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize("inactive_party", ["issuer", "subject"])
def test_capability_issuance_rejects_inactive_issuer_or_subject(
    capability_authority_runtime: None,
    inactive_party: str,
) -> None:
    with TestClient(app) as client:
        _register(client, "cap-issuer")
        _register(client, "cap-subject")
        inactive_agent = f"cap-{inactive_party}"
        suspended = client.patch(
            f"/v1/identity/agents/{inactive_agent}",
            json={"status": "suspended"},
            headers={**_headers(), "Idempotency-Key": f"s165-suspend-{inactive_party}"},
        )
        assert suspended.status_code == 200, suspended.text

        denied = client.post(
            "/v1/identity/capability-tokens/issue",
            json=_capability_payload("cap-issuer", "cap-subject"),
            headers=_headers(),
        )

    assert denied.status_code in {400, 403, 409}, denied.text


@pytest.mark.parametrize(
    ("subject_api_key", "subject_tenant"),
    [("owner-b-key", "tenant-a"), ("owner-a-key", "tenant-b")],
)
def test_capability_issuance_rejects_cross_boundary_subject(
    capability_authority_runtime: None,
    subject_api_key: str,
    subject_tenant: str,
) -> None:
    with TestClient(app) as client:
        _register(client, "boundary-issuer")
        _register(
            client,
            "boundary-subject",
            api_key=subject_api_key,
            tenant_id=subject_tenant,
        )
        denied = client.post(
            "/v1/identity/capability-tokens/issue",
            json=_capability_payload("boundary-issuer", "boundary-subject"),
            headers=_headers(),
        )

    assert denied.status_code == 404, denied.text


def test_agent_bound_caller_can_only_issue_capabilities_as_self(
    capability_authority_runtime: None,
) -> None:
    with TestClient(app) as client:
        _register(client, "agent-caller")
        _register(client, "other-issuer")
        _register(client, "cap-recipient")
        secret = _issue_agent_credential(client, "agent-caller")

        denied = client.post(
            "/v1/identity/capability-tokens/issue",
            json=_capability_payload("other-issuer", "cap-recipient"),
            headers=_agent_headers(secret),
        )
        allowed = client.post(
            "/v1/identity/capability-tokens/issue",
            json=_capability_payload("agent-caller", "cap-recipient"),
            headers=_agent_headers(secret),
        )

    assert denied.status_code == 403, denied.text
    assert allowed.status_code == 200, allowed.text


def test_capability_verification_requires_persisted_audience_and_resource_context(
    capability_authority_runtime: None,
) -> None:
    with TestClient(app) as client:
        _register(client, "context-issuer")
        _register(client, "context-subject")
        token = _issue_capability(client, "context-issuer", "context-subject")

        matching = client.post(
            "/v1/identity/capability-tokens/verify",
            json={
                "token": token,
                "audience": CAPABILITY_AUDIENCE,
                "resource": CAPABILITY_RESOURCE,
            },
            headers=_headers(),
        )
        missing_audience = client.post(
            "/v1/identity/capability-tokens/verify",
            json={"token": token, "resource": CAPABILITY_RESOURCE},
            headers=_headers(),
        )
        missing_resource = client.post(
            "/v1/identity/capability-tokens/verify",
            json={"token": token, "audience": CAPABILITY_AUDIENCE},
            headers=_headers(),
        )
        wrong_audience = client.post(
            "/v1/identity/capability-tokens/verify",
            json={
                "token": token,
                "audience": "agenthub://wrong-worker",
                "resource": CAPABILITY_RESOURCE,
            },
            headers=_headers(),
        )
        wrong_resource = client.post(
            "/v1/identity/capability-tokens/verify",
            json={
                "token": token,
                "audience": CAPABILITY_AUDIENCE,
                "resource": "urn:agenthub:resource:other",
            },
            headers=_headers(),
        )

    assert matching.status_code == 200, matching.text
    assert matching.json()["valid"] is True
    for rejected in (
        missing_audience,
        missing_resource,
        wrong_audience,
        wrong_resource,
    ):
        assert rejected.status_code == 200, rejected.text
        assert rejected.json()["valid"] is False


def test_capability_ip_caveat_uses_http_peer_and_rejects_body_override(
    capability_authority_runtime: None,
) -> None:
    with TestClient(app) as client:
        _register(client, "ip-issuer")
        _register(client, "ip-subject")
        token = _issue_capability(
            client,
            "ip-issuer",
            "ip-subject",
            caveats=[{"type": "ip", "allowed_ips": ["testclient"]}],
        )

        derived_from_request = client.post(
            "/v1/identity/capability-tokens/verify",
            json={
                "token": token,
                "audience": CAPABILITY_AUDIENCE,
                "resource": CAPABILITY_RESOURCE,
            },
            headers=_headers(),
        )
        forged_body_context = client.post(
            "/v1/identity/capability-tokens/verify",
            json={
                "token": token,
                "audience": CAPABILITY_AUDIENCE,
                "resource": CAPABILITY_RESOURCE,
                "source_ip": "testclient",
            },
            headers=_headers(),
        )

    assert derived_from_request.status_code == 200, derived_from_request.text
    assert derived_from_request.json()["valid"] is True
    assert forged_body_context.status_code == 422, forged_body_context.text


@pytest.mark.parametrize(
    "denied_headers",
    [_headers("owner-b-key", "tenant-a"), _headers("owner-a-key", "tenant-b")],
)
def test_capability_token_objects_are_nondisclosing_across_boundaries(
    capability_authority_runtime: None,
    denied_headers: dict[str, str],
) -> None:
    with TestClient(app) as client:
        _register(client, "token-owner-issuer")
        _register(client, "token-owner-subject")
        token = _issue_capability(client, "token-owner-issuer", "token-owner-subject")
        token_id = str(token["token_id"])

        denied_read = client.get(
            f"/v1/identity/capability-tokens/{token_id}",
            headers=denied_headers,
        )
        denied_list = client.get(
            "/v1/identity/capability-tokens", headers=denied_headers
        )
        denied_revoke = client.post(
            f"/v1/identity/capability-tokens/{token_id}/revoke",
            json={"reason": "cross-boundary-attempt"},
            headers={**denied_headers, "Idempotency-Key": "s165-cross-token-revoke"},
        )
        owner_read = client.get(
            f"/v1/identity/capability-tokens/{token_id}",
            headers=_headers(),
        )
        owner_verify = client.post(
            "/v1/identity/capability-tokens/verify",
            json={
                "token": token,
                "audience": CAPABILITY_AUDIENCE,
                "resource": CAPABILITY_RESOURCE,
            },
            headers=_headers(),
        )

    assert denied_read.status_code == 404, denied_read.text
    assert denied_list.status_code == 200, denied_list.text
    assert denied_list.json() == {"count": 0, "tokens": []}
    assert denied_revoke.status_code == 404, denied_revoke.text
    assert owner_read.status_code == 200, owner_read.text
    assert owner_read.json()["token_id"] == token_id
    assert owner_verify.status_code == 200, owner_verify.text
    assert owner_verify.json()["valid"] is True


def test_did_creation_requires_active_owned_identity_and_agent_self(
    capability_authority_runtime: None,
) -> None:
    with TestClient(app) as client:
        missing_identity = client.post(
            "/v1/identity/dids",
            json={"agent_id": "unregistered-agent"},
            headers=_headers(),
        )

        _register(client, "suspended-did-agent")
        suspended = client.patch(
            "/v1/identity/agents/suspended-did-agent",
            json={"status": "suspended"},
            headers={**_headers(), "Idempotency-Key": "s165-suspend-did-agent"},
        )
        assert suspended.status_code == 200, suspended.text
        inactive_identity = client.post(
            "/v1/identity/dids",
            json={"agent_id": "suspended-did-agent"},
            headers=_headers(),
        )

        _register(client, "did-agent-caller")
        _register(client, "did-other-agent")
        secret = _issue_agent_credential(client, "did-agent-caller")
        impersonated = client.post(
            "/v1/identity/dids",
            json={"agent_id": "did-other-agent"},
            headers=_agent_headers(secret),
        )
        own = client.post(
            "/v1/identity/dids",
            json={"agent_id": "did-agent-caller"},
            headers=_agent_headers(secret),
        )

    assert missing_identity.status_code == 404, missing_identity.text
    assert inactive_identity.status_code in {400, 403, 409}, inactive_identity.text
    assert impersonated.status_code == 403, impersonated.text
    assert own.status_code == 200, own.text


@pytest.mark.parametrize(
    "denied_headers",
    [_headers("owner-b-key", "tenant-a"), _headers("owner-a-key", "tenant-b")],
)
def test_did_read_list_and_deactivate_are_nondisclosing_across_boundaries(
    capability_authority_runtime: None,
    denied_headers: dict[str, str],
) -> None:
    with TestClient(app) as client:
        _register(client, "owned-did-agent")
        did = str(_create_did(client, "owned-did-agent")["id"])
        suffix = _did_suffix(did)

        denied_read = client.get(
            f"/v1/identity/dids/{suffix}/resolve", headers=denied_headers
        )
        denied_list = client.get(
            "/v1/identity/dids?active_only=false",
            headers=denied_headers,
        )
        denied_deactivate = client.post(
            f"/v1/identity/dids/{suffix}/deactivate",
            json={"reason": "cross-boundary-attempt"},
            headers=denied_headers,
        )
        owner_read = client.get(
            f"/v1/identity/dids/{suffix}/resolve",
            headers=_headers(),
        )

    assert denied_read.status_code == 404, denied_read.text
    assert denied_list.status_code == 200, denied_list.text
    assert denied_list.json() == {"count": 0, "dids": []}
    assert denied_deactivate.status_code == 404, denied_deactivate.text
    assert owner_read.status_code == 200, owner_read.text
    assert owner_read.json()["didResolutionMetadata"]["deactivated"] is False


def test_did_deactivation_is_monotonic(
    capability_authority_runtime: None,
) -> None:
    with TestClient(app) as client:
        _register(client, "monotonic-did-agent")
        did = str(_create_did(client, "monotonic-did-agent")["id"])
        suffix = _did_suffix(did)
        deactivated = client.post(
            f"/v1/identity/dids/{suffix}/deactivate",
            json={"reason": "retired"},
            headers=_headers(),
        )
        recreated = client.post(
            "/v1/identity/dids",
            json={"agent_id": "monotonic-did-agent"},
            headers=_headers(),
        )
        resolved = client.get(
            f"/v1/identity/dids/{suffix}/resolve",
            headers=_headers(),
        )

    assert deactivated.status_code == 200, deactivated.text
    assert recreated.status_code == 409, recreated.text
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["didResolutionMetadata"]["deactivated"] is True


@pytest.mark.parametrize(
    ("foreign_api_key", "foreign_tenant"),
    [("owner-b-key", "tenant-a"), ("owner-a-key", "tenant-b")],
)
def test_vc_issuance_rejects_cross_boundary_subject_did(
    capability_authority_runtime: None,
    foreign_api_key: str,
    foreign_tenant: str,
) -> None:
    with TestClient(app) as client:
        _register(client, "vc-local-issuer")
        local_issuer_did = str(_create_did(client, "vc-local-issuer")["id"])
        _register(
            client,
            "vc-foreign-subject",
            api_key=foreign_api_key,
            tenant_id=foreign_tenant,
        )
        foreign_subject_did = str(
            _create_did(
                client,
                "vc-foreign-subject",
                api_key=foreign_api_key,
                tenant_id=foreign_tenant,
            )["id"]
        )
        denied = client.post(
            "/v1/identity/vcs/issue",
            json={
                "issuer_did": local_issuer_did,
                "subject_did": foreign_subject_did,
                "credential_type": "AgentIdentityCredential",
                "ttl_seconds": 3600,
            },
            headers=_headers(),
        )

    assert denied.status_code == 404, denied.text


def test_vc_issuance_rejects_inactive_subject_identity_and_did(
    capability_authority_runtime: None,
) -> None:
    with TestClient(app) as client:
        _register(client, "vc-active-issuer")
        _register(client, "vc-inactive-subject")
        issuer_did = str(_create_did(client, "vc-active-issuer")["id"])
        subject_did = str(_create_did(client, "vc-inactive-subject")["id"])
        suspended = client.patch(
            "/v1/identity/agents/vc-inactive-subject",
            json={"status": "suspended"},
            headers={**_headers(), "Idempotency-Key": "s165-suspend-vc-subject"},
        )
        assert suspended.status_code == 200, suspended.text
        denied_inactive_identity = client.post(
            "/v1/identity/vcs/issue",
            json={
                "issuer_did": issuer_did,
                "subject_did": subject_did,
                "ttl_seconds": 3600,
            },
            headers=_headers(),
        )

        reactivated = client.patch(
            "/v1/identity/agents/vc-inactive-subject",
            json={"status": "active"},
            headers={**_headers(), "Idempotency-Key": "s165-reactivate-vc-subject"},
        )
        assert reactivated.status_code == 200, reactivated.text
        deactivated = client.post(
            f"/v1/identity/dids/{_did_suffix(subject_did)}/deactivate",
            json={"reason": "retired-subject"},
            headers=_headers(),
        )
        assert deactivated.status_code == 200, deactivated.text
        denied_inactive_did = client.post(
            "/v1/identity/vcs/issue",
            json={
                "issuer_did": issuer_did,
                "subject_did": subject_did,
                "ttl_seconds": 3600,
            },
            headers=_headers(),
        )

    assert denied_inactive_identity.status_code in {400, 403, 409}, (
        denied_inactive_identity.text
    )
    assert denied_inactive_did.status_code in {400, 403, 409}, denied_inactive_did.text


def test_agent_bound_vc_issuer_must_be_calling_agent_did(
    capability_authority_runtime: None,
) -> None:
    with TestClient(app) as client:
        for agent_id in ("vc-agent-caller", "vc-other-issuer", "vc-recipient"):
            _register(client, agent_id)
        caller_did = str(_create_did(client, "vc-agent-caller")["id"])
        other_did = str(_create_did(client, "vc-other-issuer")["id"])
        recipient_did = str(_create_did(client, "vc-recipient")["id"])
        secret = _issue_agent_credential(client, "vc-agent-caller")

        denied = client.post(
            "/v1/identity/vcs/issue",
            json={
                "issuer_did": other_did,
                "subject_did": recipient_did,
                "ttl_seconds": 3600,
            },
            headers=_agent_headers(secret),
        )
        allowed = client.post(
            "/v1/identity/vcs/issue",
            json={
                "issuer_did": caller_did,
                "subject_did": recipient_did,
                "ttl_seconds": 3600,
            },
            headers=_agent_headers(secret),
        )

    assert denied.status_code == 403, denied.text
    assert allowed.status_code == 200, allowed.text


@pytest.mark.parametrize(
    "denied_headers",
    [_headers("owner-b-key", "tenant-a"), _headers("owner-a-key", "tenant-b")],
)
def test_vc_read_list_and_revoke_are_nondisclosing_across_boundaries(
    capability_authority_runtime: None,
    denied_headers: dict[str, str],
) -> None:
    with TestClient(app) as client:
        _register(client, "vc-owned-issuer")
        _register(client, "vc-owned-subject")
        issuer_did = str(_create_did(client, "vc-owned-issuer")["id"])
        subject_did = str(_create_did(client, "vc-owned-subject")["id"])
        vc = _issue_vc(client, issuer_did, subject_did)
        vc_id = str(vc["vc_id"])
        suffix = _vc_suffix(vc_id)

        denied_read = client.get(
            f"/v1/identity/vcs/{suffix}/verify", headers=denied_headers
        )
        denied_list = client.get(
            "/v1/identity/vcs?active_only=false",
            headers=denied_headers,
        )
        denied_revoke = client.post(
            f"/v1/identity/vcs/{suffix}/revoke",
            json={"reason": "cross-boundary-attempt"},
            headers=denied_headers,
        )
        owner_read = client.get(f"/v1/identity/vcs/{suffix}/verify", headers=_headers())

    assert denied_read.status_code == 404, denied_read.text
    assert denied_list.status_code == 200, denied_list.text
    assert denied_list.json() == {"count": 0, "credentials": []}
    assert denied_revoke.status_code == 404, denied_revoke.text
    assert owner_read.status_code == 200, owner_read.text
    assert owner_read.json()["valid"] is True


def test_vc_claims_cannot_overwrite_credential_subject_id(
    capability_authority_runtime: None,
) -> None:
    with TestClient(app) as client:
        _register(client, "claims-issuer")
        _register(client, "claims-subject")
        _register(client, "claims-attacker")
        issuer_did = str(_create_did(client, "claims-issuer")["id"])
        subject_did = str(_create_did(client, "claims-subject")["id"])
        attacker_did = str(_create_did(client, "claims-attacker")["id"])
        denied = client.post(
            "/v1/identity/vcs/issue",
            json={
                "issuer_did": issuer_did,
                "subject_did": subject_did,
                "claims": {"id": attacker_did, "role": "admin"},
                "ttl_seconds": 3600,
            },
            headers=_headers(),
        )

    assert denied.status_code == 400, denied.text


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/v1/identity/capability-tokens/verify", {"token": {}}),
        (
            "/v1/identity/capability-tokens/issue",
            {
                **_capability_payload("malformed-agent", "malformed-agent"),
                "caveats": [{"type": "ip", "allowed_ips": "127.0.0.1"}],
            },
        ),
        (
            "/v1/identity/dids",
            {
                "agent_id": "malformed-agent",
                "service_endpoints": [{"type": "AgentService"}],
            },
        ),
    ],
)
def test_malformed_authority_inputs_return_deterministic_validation_errors(
    capability_authority_runtime: None,
    path: str,
    payload: dict[str, Any],
) -> None:
    with TestClient(app, raise_server_exceptions=False) as client:
        _register(client, "malformed-agent")
        response = client.post(path, json=payload, headers=_headers())

    assert response.status_code == 422, response.text
