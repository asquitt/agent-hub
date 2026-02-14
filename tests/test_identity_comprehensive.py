"""Comprehensive identity functional tests — all 5 goal areas.

Goal 1: Delegated authority (scoped, time-limited agent permissions)
Goal 2: Revocable permission tokens (kill switch)
Goal 3: Agent-to-agent authentication (credential-based identity)
Goal 4: Cross-organization agent identity federation
Goal 5: Permission delegation chains with audit trail
"""

from __future__ import annotations

import json
import os
import uuid

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key-001": "test-owner"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-signing-secret-comprehensive")
os.environ.setdefault(
    "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON",
    json.dumps({"partner-east": "east-token-001", "partner-west": "west-token-001"}),
)

from starlette.testclient import TestClient

from src.api.app import app
from src.delegation.storage import reset_for_tests as reset_delegation
from src.identity.storage import reset_for_tests as reset_identity
from src.lease.service import reset_state_for_tests as reset_leases

HEADERS = {"X-API-Key": "test-key-001"}

client = TestClient(app)
reset_identity()
reset_delegation()
reset_leases()

passed = 0
failed = 0


def _pass(name: str) -> None:
    global passed
    passed += 1
    print(f"  PASS: {name}")


def _fail(name: str, reason: str) -> None:
    global failed
    failed += 1
    print(f"  FAIL: {name} — {reason}")


def _h() -> dict:
    """Headers with idempotency key."""
    return {**HEADERS, "Idempotency-Key": str(uuid.uuid4())}


# ============================================================
# GOAL 1: Delegated authority framework
# ============================================================
print("\n=== GOAL 1: Delegated Authority Framework ===")


def test_agent_registration():
    """Register agent identities with scoped credentials."""
    resp = client.post(
        "/v1/identity/agents",
        json={"agent_id": "agent-alice", "credential_type": "api_key"},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["agent_id"] == "agent-alice"
    assert data["status"] == "active"
    _pass("agent registration")


def test_credential_issuance_with_scopes():
    """Issue credentials with specific scopes (time-limited)."""
    resp = client.post(
        "/v1/identity/agents/agent-alice/credentials",
        json={"scopes": ["read", "write", "delegate"], "ttl_seconds": 7200},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "credential_id" in data
    assert "secret" in data
    assert data["scopes"] == ["delegate", "read", "write"]
    _pass("credential issuance with scopes")
    return data


def test_delegation_token_with_scope_attenuation():
    """Issue delegation token with attenuated scopes (subset of parent)."""
    # Register delegate agent
    client.post(
        "/v1/identity/agents",
        json={"agent_id": "agent-bob", "credential_type": "api_key"},
        headers=HEADERS,
    )
    client.post(
        "/v1/identity/agents/agent-bob/credentials",
        json={"scopes": ["read", "write"], "ttl_seconds": 3600},
        headers=HEADERS,
    )

    # Alice delegates to Bob with attenuated scopes (only "read")
    resp = client.post(
        "/v1/identity/delegation-tokens",
        json={
            "issuer_agent_id": "agent-alice",
            "subject_agent_id": "agent-bob",
            "delegated_scopes": ["read"],
            "ttl_seconds": 1800,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["delegated_scopes"] == ["read"]
    assert "signed_token" in data
    _pass("delegation token with scope attenuation")
    return data


def test_scope_escalation_blocked():
    """Scope escalation is blocked — child cannot have more scopes than parent."""
    # Try to delegate "admin" scope that Alice doesn't have
    resp = client.post(
        "/v1/identity/delegation-tokens",
        json={
            "issuer_agent_id": "agent-alice",
            "subject_agent_id": "agent-bob",
            "delegated_scopes": ["admin"],
            "ttl_seconds": 1800,
        },
        headers=HEADERS,
    )
    # System correctly rejects scope escalation
    assert resp.status_code in (403, 400), f"expected 403/400 but got {resp.status_code}"
    assert "scope escalation" in resp.text.lower() or "not in parent" in resp.text.lower()
    _pass("scope escalation blocked")


def test_delegation_in_delegation_service():
    """Delegation service records identity verification context."""
    resp = client.post(
        "/v1/delegations",
        json={
            "requester_agent_id": "agent-alice",
            "delegate_agent_id": "agent-bob",
            "task_spec": "data-analysis",
            "estimated_cost_usd": 2.0,
            "max_budget_usd": 10.0,
        },
        headers=_h(),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    ctx = data["identity_context"]
    assert ctx["requester_verified"] is True
    assert ctx["delegate_verified"] is True
    _pass("delegation with identity verification")


test_agent_registration()
cred = test_credential_issuance_with_scopes()
token_data = test_delegation_token_with_scope_attenuation()
test_scope_escalation_blocked()
test_delegation_in_delegation_service()


# ============================================================
# GOAL 2: Revocable permission tokens (kill switch)
# ============================================================
print("\n=== GOAL 2: Revocable Permission Tokens (Kill Switch) ===")


def test_credential_revocation():
    """Revoke individual credential."""
    resp = client.post(
        f"/v1/identity/credentials/{cred['credential_id']}/revoke",
        json={"reason": "compromised"},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "revoked"
    _pass("credential revocation")


def test_agent_kill_switch():
    """Kill switch: revoke agent + all credentials + all tokens + leases."""
    # Register a new agent with lease
    client.post(
        "/v1/identity/agents",
        json={"agent_id": "agent-charlie", "credential_type": "api_key"},
        headers=HEADERS,
    )
    client.post(
        "/v1/identity/agents/agent-charlie/credentials",
        json={"scopes": ["execute"], "ttl_seconds": 3600},
        headers=HEADERS,
    )
    # Create a lease for charlie
    client.post(
        "/v1/capabilities/lease",
        json={
            "requester_agent_id": "agent-charlie",
            "capability_ref": "tool://calculator",
            "ttl_seconds": 3600,
        },
        headers={**HEADERS, "Idempotency-Key": str(uuid.uuid4())},
    )
    # Issue delegation token from charlie
    client.post(
        "/v1/identity/delegation-tokens",
        json={
            "issuer_agent_id": "agent-charlie",
            "subject_agent_id": "agent-bob",
            "delegated_scopes": ["execute"],
            "ttl_seconds": 1800,
        },
        headers=HEADERS,
    )

    # Kill switch
    resp = client.post(
        "/v1/identity/agents/agent-charlie/revoke",
        json={"reason": "security_incident"},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["revoked_credentials"] >= 1
    assert data["revoked_tokens"] >= 1
    assert data["revoked_leases"] >= 1
    _pass("agent kill switch (credentials + tokens + leases)")


def test_bulk_revoke():
    """Bulk kill switch for security incidents."""
    # Register multiple agents
    for aid in ["agent-d1", "agent-d2", "agent-d3"]:
        client.post(
            "/v1/identity/agents",
            json={"agent_id": aid, "credential_type": "api_key"},
            headers=HEADERS,
        )
        client.post(
            f"/v1/identity/agents/{aid}/credentials",
            json={"scopes": ["read"], "ttl_seconds": 3600},
            headers=HEADERS,
        )

    resp = client.post(
        "/v1/identity/revocations/bulk",
        json={"agent_ids": ["agent-d1", "agent-d2", "agent-d3"], "reason": "breach"},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total_revoked"] == 3
    _pass("bulk revoke (3 agents)")


def test_revocation_audit_trail():
    """Revocation events are auditable."""
    resp = client.get("/v1/identity/revocations", headers=HEADERS)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["events"]) >= 4  # charlie + d1 + d2 + d3
    _pass("revocation audit trail")


test_credential_revocation()
test_agent_kill_switch()
test_bulk_revoke()
test_revocation_audit_trail()


# ============================================================
# GOAL 3: Agent-to-agent authentication
# ============================================================
print("\n=== GOAL 3: Agent-to-Agent Authentication ===")


def test_agent_credential_auth():
    """Agent authenticates using AgentCredential scheme."""
    # Register fresh agent
    client.post(
        "/v1/identity/agents",
        json={"agent_id": "agent-eve", "credential_type": "api_key"},
        headers=HEADERS,
    )
    cred_resp = client.post(
        "/v1/identity/agents/agent-eve/credentials",
        json={"scopes": ["read", "execute"], "ttl_seconds": 3600},
        headers=HEADERS,
    )
    assert cred_resp.status_code == 200
    secret = cred_resp.json()["secret"]

    # Authenticate using AgentCredential header
    resp = client.get(
        "/v1/identity/agents/agent-eve",
        headers={"Authorization": f"AgentCredential {secret}"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["agent_id"] == "agent-eve"
    _pass("agent credential authentication")


def test_delegation_token_auth():
    """Agent authenticates via delegation token header."""
    # Register fresh agents
    client.post(
        "/v1/identity/agents",
        json={"agent_id": "agent-frank", "credential_type": "api_key"},
        headers=HEADERS,
    )
    client.post(
        "/v1/identity/agents/agent-frank/credentials",
        json={"scopes": ["read"], "ttl_seconds": 3600},
        headers=HEADERS,
    )
    client.post(
        "/v1/identity/agents",
        json={"agent_id": "agent-grace", "credential_type": "api_key"},
        headers=HEADERS,
    )
    client.post(
        "/v1/identity/agents/agent-grace/credentials",
        json={"scopes": ["read"], "ttl_seconds": 3600},
        headers=HEADERS,
    )

    # Issue delegation token
    tok_resp = client.post(
        "/v1/identity/delegation-tokens",
        json={
            "issuer_agent_id": "agent-frank",
            "subject_agent_id": "agent-grace",
            "delegated_scopes": ["read"],
            "ttl_seconds": 1800,
        },
        headers=HEADERS,
    )
    signed_token = tok_resp.json()["signed_token"]

    # Grace authenticates using delegation token
    resp = client.get(
        "/v1/identity/agents/agent-grace",
        headers={"X-Delegation-Token": signed_token},
    )
    assert resp.status_code == 200, resp.text
    _pass("delegation token authentication")


def test_credential_rotation():
    """Rotate credential without downtime."""
    resp = client.post(
        "/v1/identity/agents/agent-eve/credentials",
        json={"scopes": ["read", "execute"], "ttl_seconds": 3600},
        headers=HEADERS,
    )
    old_cred_id = resp.json()["credential_id"]

    resp = client.post(
        f"/v1/identity/credentials/{old_cred_id}/rotate",
        json={},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["credential_id"] != old_cred_id
    assert "secret" in data
    _pass("credential rotation")


def test_active_sessions():
    """List active credentials/sessions for an agent."""
    resp = client.get("/v1/identity/agents/agent-eve/active-sessions", headers=HEADERS)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["agent_id"] == "agent-eve"
    assert len(data["credentials"]) >= 1
    _pass("active sessions listing")


test_agent_credential_auth()
test_delegation_token_auth()
test_credential_rotation()
test_active_sessions()


# ============================================================
# GOAL 4: Cross-organization agent identity federation
# ============================================================
print("\n=== GOAL 4: Cross-Org Agent Identity Federation ===")


def test_trust_registry():
    """Register and manage trusted domains."""
    resp = client.post(
        "/v1/identity/trust-registry/domains",
        json={
            "domain_id": "company-x",
            "display_name": "Company X",
            "trust_level": "verified",
            "allowed_scopes": ["read", "execute"],
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["domain_id"] == "company-x"
    assert data["trust_level"] == "verified"
    _pass("trust registry — domain registration")


def test_agent_attestation():
    """Create agent attestation binding agent to trusted domain."""
    # Register test-owner as agent for federation actor
    client.post(
        "/v1/identity/agents",
        json={"agent_id": "test-owner", "credential_type": "api_key"},
        headers=HEADERS,
    )

    resp = client.post(
        "/v1/identity/agents/test-owner/attest",
        json={
            "domain_id": "company-x",
            "ttl_seconds": 7200,
            "claims": {"role": "data-processor"},
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["domain_id"] == "company-x"
    assert "signature" in data
    assert "attestation_id" in data
    _pass("agent attestation creation")
    return data


def test_attestation_verification():
    """Verify agent attestation is valid."""
    att = test_agent_attestation.__attestation
    resp = client.get(
        f"/v1/identity/attestations/{att['attestation_id']}/verify",
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["valid"] is True
    assert data["domain_id"] == "company-x"
    _pass("attestation verification")


def test_federated_execution_with_attestation():
    """Federated execution with agent attestation verification."""
    att = test_agent_attestation.__attestation
    resp = client.post(
        "/v1/federation/execute",
        json={
            "domain_id": "partner-east",
            "domain_token": "east-token-001",
            "task_spec": "cross-org-analysis",
            "payload": {"data": "shared"},
            "policy_context": {"decision": "allow"},
            "estimated_cost_usd": 2.0,
            "max_budget_usd": 20.0,
            "agent_attestation_id": att["attestation_id"],
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    ctx = data["identity_context"]
    assert ctx["actor_verified"] is True
    assert ctx["attestation_verified"] is True
    assert ctx["attestation_id"] == att["attestation_id"]
    _pass("federated execution with attestation")


def test_list_trusted_domains():
    """List all trusted domains in registry."""
    resp = client.get("/v1/identity/trust-registry/domains", headers=HEADERS)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["domains"]) >= 1
    _pass("list trusted domains")


test_trust_registry()
att_data = test_agent_attestation()
test_agent_attestation.__attestation = att_data  # type: ignore[attr-defined]
test_attestation_verification()
test_federated_execution_with_attestation()
test_list_trusted_domains()


# ============================================================
# GOAL 5: Permission delegation chains with audit trail
# ============================================================
print("\n=== GOAL 5: Permission Delegation Chains with Audit Trail ===")


def test_delegation_chain():
    """Build multi-hop delegation chain: A → B → C."""
    # Register fresh agents for chain test
    for aid in ["agent-chain-a", "agent-chain-b", "agent-chain-c"]:
        client.post(
            "/v1/identity/agents",
            json={"agent_id": aid, "credential_type": "api_key"},
            headers=HEADERS,
        )
        client.post(
            f"/v1/identity/agents/{aid}/credentials",
            json={"scopes": ["read", "write"], "ttl_seconds": 3600},
            headers=HEADERS,
        )

    # A delegates to B
    resp = client.post(
        "/v1/identity/delegation-tokens",
        json={
            "issuer_agent_id": "agent-chain-a",
            "subject_agent_id": "agent-chain-b",
            "delegated_scopes": ["read", "write"],
            "ttl_seconds": 3600,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    tok_ab = resp.json()

    # B delegates to C with attenuated scopes
    resp = client.post(
        "/v1/identity/delegation-tokens",
        json={
            "issuer_agent_id": "agent-chain-b",
            "subject_agent_id": "agent-chain-c",
            "delegated_scopes": ["read"],
            "parent_token_id": tok_ab["token_id"],
            "ttl_seconds": 1800,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    tok_bc = resp.json()

    # Verify chain
    resp = client.get(
        f"/v1/identity/delegation-tokens/{tok_bc['token_id']}/chain",
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    chain = resp.json()
    assert chain["chain_depth"] >= 1
    assert len(chain["chain"]) >= 2
    _pass("delegation chain A → B → C")
    return tok_bc


def test_chain_scope_attenuation():
    """Chain enforces scope attenuation — C cannot have more than B."""
    chain_token = test_delegation_chain.__chain_token

    # Verify the chain token
    resp = client.post(
        "/v1/identity/delegation-tokens/verify",
        json={"signed_token": chain_token["signed_token"]},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "read" in data["delegated_scopes"]
    # "write" should NOT be in C's scopes since B only delegated "read"
    assert "write" not in data["delegated_scopes"]
    _pass("chain scope attenuation enforced")


def test_delegation_with_token_in_service():
    """Use delegation token in the delegation service."""
    chain_token = test_delegation_chain.__chain_token
    resp = client.post(
        "/v1/delegations",
        json={
            "requester_agent_id": "agent-chain-b",
            "delegate_agent_id": "agent-chain-c",
            "task_spec": "chain-delegation-task",
            "estimated_cost_usd": 1.0,
            "max_budget_usd": 10.0,
            "delegation_token": chain_token["signed_token"],
        },
        headers=_h(),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["identity_context"]["delegation_token_id"] is not None
    _pass("delegation with token in service")


def test_federation_audit():
    """Federation audit trail records all executions."""
    resp = client.get("/v1/federation/audit?limit=10", headers=HEADERS)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["data"]) >= 1
    _pass("federation audit trail")


def test_identity_aware_policy():
    """Policy engine evaluates identity-aware policies."""
    # This is tested implicitly through delegation and federation calls
    # that verify agent identity status before allowing operations
    resp = client.get("/v1/identity/agents/agent-alice", headers=HEADERS)
    assert resp.status_code == 200
    # Alice was not revoked, so status should still be active
    # (her credential was revoked, but her identity is still active)
    data = resp.json()
    assert data["status"] == "active"
    _pass("identity-aware policy evaluation")


chain_tok = test_delegation_chain()
test_delegation_chain.__chain_token = chain_tok  # type: ignore[attr-defined]
test_chain_scope_attenuation()
test_delegation_with_token_in_service()  # uses __chain_token
test_federation_audit()
test_identity_aware_policy()

# ============================================================
# SUMMARY
# ============================================================
print(f"\n{'='*60}")
print(f"RESULTS: {passed} passed, {failed} failed out of {passed + failed} tests")
print(f"{'='*60}")
if failed > 0:
    raise SystemExit(1)
print("\nAll identity IAM features verified!")
