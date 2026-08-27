"""End-to-end identity tests covering the five original IAM goals."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from src.api.app import app
from src.billing.storage import reset_for_tests as reset_billing
from src.cost_governance.storage import reset_for_tests as reset_cost
from src.delegation.storage import reset_for_tests as reset_delegation
from src.identity.storage import reset_for_tests as reset_identity
from src.lease.service import reset_state_for_tests as reset_leases
from src.runtime.storage import reset_for_tests as reset_runtime

HEADERS = {"X-API-Key": "test-key-001"}


def _write_headers() -> dict[str, str]:
    return {**HEADERS, "Idempotency-Key": str(uuid.uuid4())}


@pytest.fixture()
def identity_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "enforce")
    monkeypatch.setenv("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key-001": "test-owner"}))
    monkeypatch.setenv("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-secret-comprehensive")
    monkeypatch.setenv("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-signing-secret-comprehensive")
    monkeypatch.setenv("AGENTHUB_POLICY_SIGNING_SECRET", "test-policy-secret-comprehensive")
    monkeypatch.setenv("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-provenance-secret-comprehensive")
    monkeypatch.setenv("AGENTHUB_VAULT_KEY", "test-vault-key-comprehensive")
    monkeypatch.setenv(
        "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON",
        json.dumps({"partner-east": "east-token-001", "partner-west": "west-token-001"}),
    )

    identity_db = tmp_path / "identity.db"
    delegation_db = tmp_path / "delegation.db"
    lease_db = tmp_path / "lease.db"
    runtime_db = tmp_path / "runtime.db"
    billing_db = tmp_path / "billing.db"
    cost_db = tmp_path / "cost.db"
    monkeypatch.setenv("AGENTHUB_IDENTITY_DB_PATH", str(identity_db))
    monkeypatch.setenv("AGENTHUB_DELEGATION_DB_PATH", str(delegation_db))
    monkeypatch.setenv("AGENTHUB_DELEGATION_RECORDS_PATH", str(tmp_path / "delegations.json"))
    monkeypatch.setenv("AGENTHUB_DELEGATION_BALANCES_PATH", str(tmp_path / "balances.json"))
    monkeypatch.setenv("AGENTHUB_LEASE_DB_PATH", str(lease_db))
    monkeypatch.setenv("AGENTHUB_RUNTIME_DB_PATH", str(runtime_db))
    monkeypatch.setenv("AGENTHUB_BILLING_DB_PATH", str(billing_db))
    monkeypatch.setenv("AGENTHUB_COST_DB_PATH", str(cost_db))
    monkeypatch.setenv("AGENTHUB_COST_EVENTS_PATH", str(tmp_path / "cost-events.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_USAGE_EVENTS_PATH", str(tmp_path / "usage-events.json"))
    monkeypatch.setenv("AGENTHUB_FEDERATION_AUDIT_PATH", str(tmp_path / "federation-audit.json"))

    reset_identity(db_path=identity_db)
    reset_delegation(db_path=delegation_db)
    reset_leases()
    reset_runtime(db_path=runtime_db)
    reset_billing(db_path=billing_db)
    reset_cost(db_path=cost_db)

    with TestClient(app) as client:
        yield client


def _register_agent(client: TestClient, agent_id: str) -> None:
    response = client.post(
        "/v1/identity/agents",
        json={"agent_id": agent_id, "credential_type": "api_key"},
        headers=HEADERS,
    )
    assert response.status_code == 200, response.text
    assert response.json()["agent_id"] == agent_id
    assert response.json()["status"] == "active"


def _issue_credential(client: TestClient, agent_id: str, scopes: list[str], ttl_seconds: int = 3600) -> dict:
    response = client.post(
        f"/v1/identity/agents/{agent_id}/credentials",
        json={"scopes": scopes, "ttl_seconds": ttl_seconds},
        headers=HEADERS,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "credential_id" in payload
    assert "secret" in payload
    return payload


def _verify_delegated_authority(client: TestClient) -> dict:
    _register_agent(client, "agent-alice")
    alice_credential = _issue_credential(client, "agent-alice", ["read", "write", "delegate"], 7200)
    assert alice_credential["scopes"] == ["delegate", "read", "write"]

    _register_agent(client, "agent-bob")
    _issue_credential(client, "agent-bob", ["read", "write"])

    token_response = client.post(
        "/v1/identity/delegation-tokens",
        json={
            "issuer_agent_id": "agent-alice",
            "subject_agent_id": "agent-bob",
            "delegated_scopes": ["read"],
            "ttl_seconds": 1800,
        },
        headers=HEADERS,
    )
    assert token_response.status_code == 200, token_response.text
    token = token_response.json()
    assert token["delegated_scopes"] == ["read"]
    assert "signed_token" in token

    escalation = client.post(
        "/v1/identity/delegation-tokens",
        json={
            "issuer_agent_id": "agent-alice",
            "subject_agent_id": "agent-bob",
            "delegated_scopes": ["admin"],
            "ttl_seconds": 1800,
        },
        headers=HEADERS,
    )
    assert escalation.status_code in (400, 403), escalation.text
    assert "scope escalation" in escalation.text.lower() or "not in parent" in escalation.text.lower()

    delegation = client.post(
        "/v1/delegations",
        json={
            "requester_agent_id": "agent-alice",
            "delegate_agent_id": "agent-bob",
            "task_spec": "data-analysis",
            "estimated_cost_usd": 2.0,
            "max_budget_usd": 10.0,
        },
        headers=_write_headers(),
    )
    assert delegation.status_code == 200, delegation.text
    assert delegation.json()["identity_context"]["requester_verified"] is True
    assert delegation.json()["identity_context"]["delegate_verified"] is True
    return alice_credential


def _verify_revocation(client: TestClient, alice_credential: dict) -> None:
    revoked = client.post(
        f"/v1/identity/credentials/{alice_credential['credential_id']}/revoke",
        json={"reason": "compromised"},
        headers=HEADERS,
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"

    _register_agent(client, "agent-charlie")
    _issue_credential(client, "agent-charlie", ["execute"])
    lease = client.post(
        "/v1/capabilities/lease",
        json={
            "requester_agent_id": "agent-charlie",
            "capability_ref": "tool://calculator",
            "ttl_seconds": 3600,
        },
        headers=_write_headers(),
    )
    assert lease.status_code == 200, lease.text
    token = client.post(
        "/v1/identity/delegation-tokens",
        json={
            "issuer_agent_id": "agent-charlie",
            "subject_agent_id": "agent-bob",
            "delegated_scopes": ["execute"],
            "ttl_seconds": 1800,
        },
        headers=HEADERS,
    )
    assert token.status_code == 200, token.text

    killed = client.post(
        "/v1/identity/agents/agent-charlie/revoke",
        json={"reason": "security_incident"},
        headers=HEADERS,
    )
    assert killed.status_code == 200, killed.text
    assert killed.json()["revoked_credentials"] >= 1
    assert killed.json()["revoked_tokens"] >= 1
    assert killed.json()["revoked_leases"] >= 1

    for agent_id in ("agent-d1", "agent-d2", "agent-d3"):
        _register_agent(client, agent_id)
        _issue_credential(client, agent_id, ["read"])
    bulk = client.post(
        "/v1/identity/revocations/bulk",
        json={"agent_ids": ["agent-d1", "agent-d2", "agent-d3"], "reason": "breach"},
        headers=HEADERS,
    )
    assert bulk.status_code == 200, bulk.text
    assert bulk.json()["total_revoked"] == 3

    audit = client.get("/v1/identity/revocations", headers=HEADERS)
    assert audit.status_code == 200, audit.text
    assert len(audit.json()["events"]) >= 4


def _verify_agent_authentication(client: TestClient) -> None:
    _register_agent(client, "agent-eve")
    eve_credential = _issue_credential(client, "agent-eve", ["read", "execute"])
    authenticated = client.get(
        "/v1/identity/agents/agent-eve",
        headers={"Authorization": f"AgentCredential {eve_credential['secret']}"},
    )
    assert authenticated.status_code == 200, authenticated.text
    assert authenticated.json()["agent_id"] == "agent-eve"

    for agent_id in ("agent-frank", "agent-grace"):
        _register_agent(client, agent_id)
        _issue_credential(client, agent_id, ["read"])
    token_response = client.post(
        "/v1/identity/delegation-tokens",
        json={
            "issuer_agent_id": "agent-frank",
            "subject_agent_id": "agent-grace",
            "delegated_scopes": ["read"],
            "ttl_seconds": 1800,
        },
        headers=HEADERS,
    )
    assert token_response.status_code == 200, token_response.text
    delegated_auth = client.get(
        "/v1/identity/agents/agent-grace",
        headers={"X-Delegation-Token": token_response.json()["signed_token"]},
    )
    assert delegated_auth.status_code == 200, delegated_auth.text

    old_credential = _issue_credential(client, "agent-eve", ["read", "execute"])
    rotated = client.post(
        f"/v1/identity/credentials/{old_credential['credential_id']}/rotate",
        json={},
        headers=HEADERS,
    )
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["credential_id"] != old_credential["credential_id"]
    assert "secret" in rotated.json()

    sessions = client.get("/v1/identity/agents/agent-eve/active-sessions", headers=HEADERS)
    assert sessions.status_code == 200, sessions.text
    assert sessions.json()["agent_id"] == "agent-eve"
    assert len(sessions.json()["credentials"]) >= 1


def _verify_federation(client: TestClient) -> None:
    domain = client.post(
        "/v1/identity/trust-registry/domains",
        json={
            "domain_id": "company-x",
            "display_name": "Company X",
            "trust_level": "verified",
            "allowed_scopes": ["read", "execute"],
        },
        headers=HEADERS,
    )
    assert domain.status_code == 200, domain.text
    assert domain.json()["domain_id"] == "company-x"
    assert domain.json()["trust_level"] == "verified"

    _register_agent(client, "test-owner")
    attestation = client.post(
        "/v1/identity/agents/test-owner/attest",
        json={"domain_id": "company-x", "ttl_seconds": 7200, "claims": {"role": "data-processor"}},
        headers=HEADERS,
    )
    assert attestation.status_code == 200, attestation.text
    attestation_data = attestation.json()
    assert attestation_data["domain_id"] == "company-x"
    assert "signature" in attestation_data

    verified = client.get(
        f"/v1/identity/attestations/{attestation_data['attestation_id']}/verify",
        headers=HEADERS,
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["valid"] is True
    assert verified.json()["domain_id"] == "company-x"

    execution = client.post(
        "/v1/federation/execute",
        json={
            "domain_id": "partner-east",
            "domain_token": "east-token-001",
            "task_spec": "cross-org-analysis",
            "payload": {"data": "shared"},
            "policy_context": {"decision": "allow"},
            "estimated_cost_usd": 2.0,
            "max_budget_usd": 20.0,
            "agent_attestation_id": attestation_data["attestation_id"],
        },
        headers=HEADERS,
    )
    assert execution.status_code == 200, execution.text
    context = execution.json()["identity_context"]
    assert context["actor_verified"] is True
    assert context["attestation_verified"] is True
    assert context["attestation_id"] == attestation_data["attestation_id"]

    domains = client.get("/v1/identity/trust-registry/domains", headers=HEADERS)
    assert domains.status_code == 200, domains.text
    assert len(domains.json()["domains"]) >= 1


def _verify_delegation_chain(client: TestClient) -> None:
    for agent_id in ("agent-chain-a", "agent-chain-b", "agent-chain-c"):
        _register_agent(client, agent_id)
        _issue_credential(client, agent_id, ["read", "write"])

    first_hop = client.post(
        "/v1/identity/delegation-tokens",
        json={
            "issuer_agent_id": "agent-chain-a",
            "subject_agent_id": "agent-chain-b",
            "delegated_scopes": ["read", "write"],
            "ttl_seconds": 3600,
        },
        headers=HEADERS,
    )
    assert first_hop.status_code == 200, first_hop.text

    second_hop = client.post(
        "/v1/identity/delegation-tokens",
        json={
            "issuer_agent_id": "agent-chain-b",
            "subject_agent_id": "agent-chain-c",
            "delegated_scopes": ["read"],
            "parent_token_id": first_hop.json()["token_id"],
            "ttl_seconds": 1800,
        },
        headers=HEADERS,
    )
    assert second_hop.status_code == 200, second_hop.text
    chain_token = second_hop.json()

    chain = client.get(
        f"/v1/identity/delegation-tokens/{chain_token['token_id']}/chain",
        headers=HEADERS,
    )
    assert chain.status_code == 200, chain.text
    assert chain.json()["chain_depth"] >= 1
    assert len(chain.json()["chain"]) >= 2

    verified = client.post(
        "/v1/identity/delegation-tokens/verify",
        json={"signed_token": chain_token["signed_token"]},
        headers=HEADERS,
    )
    assert verified.status_code == 200, verified.text
    assert "read" in verified.json()["delegated_scopes"]
    assert "write" not in verified.json()["delegated_scopes"]

    delegated = client.post(
        "/v1/delegations",
        json={
            "requester_agent_id": "agent-chain-b",
            "delegate_agent_id": "agent-chain-c",
            "task_spec": "chain-delegation-task",
            "estimated_cost_usd": 1.0,
            "max_budget_usd": 10.0,
            "delegation_token": chain_token["signed_token"],
        },
        headers=_write_headers(),
    )
    assert delegated.status_code == 200, delegated.text
    assert delegated.json()["identity_context"]["delegation_token_id"] is not None

    federation_audit = client.get("/v1/federation/audit?limit=10", headers=HEADERS)
    assert federation_audit.status_code == 200, federation_audit.text
    assert len(federation_audit.json()["data"]) >= 1

    alice = client.get("/v1/identity/agents/agent-alice", headers=HEADERS)
    assert alice.status_code == 200, alice.text
    assert alice.json()["status"] == "active"


def test_identity_comprehensive_flow(identity_client: TestClient) -> None:
    """Verify delegated authority, revocation, authentication, federation, and chains."""
    alice_credential = _verify_delegated_authority(identity_client)
    _verify_revocation(identity_client, alice_credential)
    _verify_agent_authentication(identity_client)
    _verify_federation(identity_client)
    _verify_delegation_chain(identity_client)
