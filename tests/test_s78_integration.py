"""S78: Integration tests — identity wired into delegation, federation, leases."""

from __future__ import annotations

import json
import os
import uuid

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key-001": "test-owner"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-signing-secret-s78")
os.environ.setdefault(
    "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON",
    json.dumps({"partner-east": "east-token-001"}),
)

from starlette.testclient import TestClient

from src.api.app import app
from src.identity.storage import reset_for_tests as reset_identity
from src.delegation.storage import reset_for_tests as reset_delegation
from src.lease.service import reset_state_for_tests as reset_leases

HEADERS = {"X-API-Key": "test-key-001"}

client = TestClient(app)
reset_identity()
reset_delegation()
reset_leases()


# ---- helpers ----

def _register_agent(agent_id: str) -> dict:
    resp = client.post(
        "/v1/identity/agents",
        json={"agent_id": agent_id, "credential_type": "api_key"},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _issue_credential(agent_id: str) -> dict:
    resp = client.post(
        f"/v1/identity/agents/{agent_id}/credentials",
        json={"scopes": ["delegate", "execute"], "ttl_seconds": 3600},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _delegation_headers() -> dict:
    return {**HEADERS, "Idempotency-Key": str(uuid.uuid4())}


def _issue_delegation_token(issuer: str, subject: str, scopes: list[str]) -> dict:
    resp = client.post(
        "/v1/identity/delegation-tokens",
        json={
            "issuer_agent_id": issuer,
            "subject_agent_id": subject,
            "delegated_scopes": scopes,
            "ttl_seconds": 3600,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---- Tests ----


def test_delegation_with_identity_context():
    """Delegation records identity verification context."""
    _register_agent("s78-req-1")
    _register_agent("s78-del-1")

    resp = client.post(
        "/v1/delegations",
        json={
            "requester_agent_id": "s78-req-1",
            "delegate_agent_id": "s78-del-1",
            "task_spec": "s78-test-task",
            "estimated_cost_usd": 1.0,
            "max_budget_usd": 10.0,
        },
        headers=_delegation_headers(),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    ctx = data["identity_context"]
    assert ctx["requester_verified"] is True
    assert ctx["delegate_verified"] is True
    assert ctx["delegation_token_id"] is None
    print("PASS: delegation with identity context")


def test_delegation_with_delegation_token():
    """Delegation can accept and verify a delegation token."""
    _register_agent("s78-req-2")
    _register_agent("s78-del-2")
    _issue_credential("s78-req-2")
    _issue_credential("s78-del-2")
    token = _issue_delegation_token("s78-req-2", "s78-del-2", ["delegate"])

    resp = client.post(
        "/v1/delegations",
        json={
            "requester_agent_id": "s78-req-2",
            "delegate_agent_id": "s78-del-2",
            "task_spec": "s78-token-task",
            "estimated_cost_usd": 1.0,
            "max_budget_usd": 10.0,
            "delegation_token": token["signed_token"],
        },
        headers=_delegation_headers(),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["identity_context"]["delegation_token_id"] == token["token_id"]
    print("PASS: delegation with delegation token")


def test_federation_with_identity_context():
    """Federated execution includes identity context when actor has an identity."""
    # The federation endpoint uses actor=owner from API key auth, which is "test-owner"
    _register_agent("test-owner")

    resp = client.post(
        "/v1/federation/execute",
        json={
            "domain_id": "partner-east",
            "domain_token": "east-token-001",
            "task_spec": "s78-fed-task",
            "payload": {"data": "test"},
            "policy_context": {"decision": "allow"},
            "estimated_cost_usd": 1.0,
            "max_budget_usd": 10.0,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    ctx = data["identity_context"]
    assert ctx["actor_verified"] is True
    assert ctx["actor_agent_id"] == "test-owner"
    assert ctx["attestation_verified"] is False
    print("PASS: federation with identity context")


def test_federation_with_attestation():
    """Federated execution verifies agent attestation."""
    # "test-owner" already registered in previous test

    # Register trusted domain
    resp = client.post(
        "/v1/identity/trust-registry/domains",
        json={
            "domain_id": "s78-partner",
            "display_name": "S78 Test Partner",
            "trust_level": "verified",
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text

    # Create attestation for "test-owner" (the actor in federation)
    resp = client.post(
        "/v1/identity/agents/test-owner/attest",
        json={
            "domain_id": "s78-partner",
            "ttl_seconds": 3600,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    attestation = resp.json()

    # Use attestation in federation
    resp = client.post(
        "/v1/federation/execute",
        json={
            "domain_id": "partner-east",
            "domain_token": "east-token-001",
            "task_spec": "s78-attested-task",
            "payload": {"data": "test"},
            "policy_context": {"decision": "allow"},
            "estimated_cost_usd": 1.0,
            "max_budget_usd": 10.0,
            "agent_attestation_id": attestation["attestation_id"],
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    ctx = data["identity_context"]
    assert ctx["attestation_verified"] is True
    assert ctx["attestation_id"] == attestation["attestation_id"]
    print("PASS: federation with attestation")


def test_lease_revocation_on_agent_revoke():
    """Revoking an agent also revokes their leases."""
    _register_agent("s78-lease-agent")

    # Create a lease
    resp = client.post(
        "/v1/capabilities/lease",
        json={
            "requester_agent_id": "s78-lease-agent",
            "capability_ref": "tool://test-cap",
            "ttl_seconds": 3600,
        },
        headers={**HEADERS, "Idempotency-Key": str(uuid.uuid4())},
    )
    assert resp.status_code == 200, resp.text
    lease = resp.json()
    assert lease["status"] == "active"

    # Revoke the agent
    resp = client.post(
        "/v1/identity/agents/s78-lease-agent/revoke",
        json={"reason": "test_revocation"},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    revoke_data = resp.json()
    assert revoke_data["revoked_leases"] >= 1

    # Verify lease is now revoked
    resp = client.get(f"/v1/capabilities/leases/{lease['lease_id']}", headers=HEADERS)
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "revoked"
    print("PASS: lease revocation on agent revoke")


def test_delegation_without_identity_module():
    """Delegation still works for unregistered agents (legacy flow)."""
    resp = client.post(
        "/v1/delegations",
        json={
            "requester_agent_id": "legacy-req-99",
            "delegate_agent_id": "legacy-del-99",
            "task_spec": "legacy-task",
            "estimated_cost_usd": 0.5,
            "max_budget_usd": 5.0,
        },
        headers=_delegation_headers(),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    ctx = data["identity_context"]
    assert ctx["requester_verified"] is False
    assert ctx["delegate_verified"] is False
    print("PASS: delegation without identity (legacy)")


def test_federation_without_identity():
    """Federation still works when actor has no identity (legacy)."""
    # Use a different API key whose owner has no registered identity
    alt_keys = json.dumps({"alt-key-99": "unknown-owner-99"})
    prev = os.environ.get("AGENTHUB_API_KEYS_JSON")
    os.environ["AGENTHUB_API_KEYS_JSON"] = alt_keys
    try:
        resp = client.post(
            "/v1/federation/execute",
            json={
                "domain_id": "partner-east",
                "domain_token": "east-token-001",
                "task_spec": "legacy-fed-task",
                "payload": {"data": "test"},
                "policy_context": {"decision": "allow"},
                "estimated_cost_usd": 1.0,
                "max_budget_usd": 10.0,
            },
            headers={"X-API-Key": "alt-key-99"},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        ctx = data["identity_context"]
        assert ctx["actor_verified"] is False
        assert ctx["attestation_verified"] is False
        print("PASS: federation without identity (legacy)")
    finally:
        if prev is not None:
            os.environ["AGENTHUB_API_KEYS_JSON"] = prev


if __name__ == "__main__":
    test_delegation_with_identity_context()
    test_delegation_with_delegation_token()
    test_federation_with_identity_context()
    test_federation_with_attestation()
    test_lease_revocation_on_agent_revoke()
    test_delegation_without_identity_module()
    test_federation_without_identity()
    print("\nAll S78 tests passed!")
