"""Tests for S161 — Delegation chain visualization."""
from __future__ import annotations

import os
os.environ.setdefault("AGENTHUB_API_KEYS_JSON", '{"dev-owner-key":"owner-dev"}')
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-secret")
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-identity-secret")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", '{"test-domain":"test-token"}')
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-provenance-secret")

from fastapi.testclient import TestClient

from src.api.app import app
from src.identity.storage import IDENTITY_STORAGE
from src.identity.credentials import issue_credential
from src.identity.delegation_tokens import issue_delegation_token
from src.runtime.chain_viz import _reset as reset_viz

client = TestClient(app)
HEADERS = {"X-API-Key": "dev-owner-key", "X-Idempotency-Key": "test-viz"}


def _setup() -> None:
    """Reset state and create test agents + delegation tokens."""
    IDENTITY_STORAGE.reset_for_tests()
    reset_viz()
    # Register two agents
    IDENTITY_STORAGE.register_identity(
        agent_id="agent-a",
        owner="owner-dev",
        credential_type="hmac-sha256",
    )
    IDENTITY_STORAGE.register_identity(
        agent_id="agent-b",
        owner="owner-dev",
        credential_type="hmac-sha256",
    )
    IDENTITY_STORAGE.register_identity(
        agent_id="agent-c",
        owner="owner-dev",
        credential_type="hmac-sha256",
    )
    # Issue credentials so delegation tokens can be created
    for aid in ["agent-a", "agent-b", "agent-c"]:
        issue_credential(agent_id=aid, scopes=["*"], owner="owner-dev")


class TestChainTreeView:
    def test_tree_view_single_token(self):
        _setup()
        token = issue_delegation_token(
            issuer_agent_id="agent-a",
            subject_agent_id="agent-b",
            delegated_scopes=["read", "write"],
            owner="owner-dev",
        )
        r = client.get(
            f"/v1/chain-viz/tokens/{token['token_id']}/tree",
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["chain_length"] == 1
        assert len(data["nodes"]) == 1
        assert data["nodes"][0]["issuer_agent_id"] == "agent-a"
        assert data["nodes"][0]["subject_agent_id"] == "agent-b"
        assert data["nodes"][0]["status"] == "active"
        assert len(data["scope_flow"]) == 1

    def test_tree_view_chained_tokens(self):
        _setup()
        token1 = issue_delegation_token(
            issuer_agent_id="agent-a",
            subject_agent_id="agent-b",
            delegated_scopes=["read", "write", "admin"],
            owner="owner-dev",
        )
        token2 = issue_delegation_token(
            issuer_agent_id="agent-b",
            subject_agent_id="agent-c",
            delegated_scopes=["read"],
            parent_token_id=token1["token_id"],
            owner="owner-dev",
        )
        r = client.get(
            f"/v1/chain-viz/tokens/{token2['token_id']}/tree",
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["chain_length"] == 2
        assert data["root_token_id"] == token1["token_id"]
        assert data["leaf_token_id"] == token2["token_id"]
        # Scope flow should show attenuation
        assert len(data["scope_flow"]) == 2

    def test_tree_view_not_found(self):
        _setup()
        r = client.get(
            "/v1/chain-viz/tokens/nonexistent/tree",
            headers=HEADERS,
        )
        assert r.status_code == 404


class TestChainRiskAnalysis:
    def test_low_risk_chain(self):
        _setup()
        token = issue_delegation_token(
            issuer_agent_id="agent-a",
            subject_agent_id="agent-b",
            delegated_scopes=["read"],
            owner="owner-dev",
        )
        r = client.get(
            f"/v1/chain-viz/tokens/{token['token_id']}/risk",
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["risk_level"] in ("low", "medium")
        assert data["chain_length"] == 1
        assert len(data["risks"]) == 0

    def test_wildcard_scope_warning(self):
        _setup()
        token = issue_delegation_token(
            issuer_agent_id="agent-a",
            subject_agent_id="agent-b",
            delegated_scopes=["*"],
            owner="owner-dev",
        )
        r = client.get(
            f"/v1/chain-viz/tokens/{token['token_id']}/risk",
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        # Should have a wildcard scope warning
        warning_codes = [w["code"] for w in data["warnings"]]
        assert "scope.wildcard" in warning_codes


class TestDelegationTrees:
    def test_list_trees(self):
        _setup()
        issue_delegation_token(
            issuer_agent_id="agent-a",
            subject_agent_id="agent-b",
            delegated_scopes=["read"],
            owner="owner-dev",
        )
        r = client.get("/v1/chain-viz/trees", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data["count"] >= 1
        assert len(data["trees"]) >= 1

    def test_list_trees_empty(self):
        _setup()
        r = client.get("/v1/chain-viz/trees", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 0


class TestChainSnapshots:
    def test_create_and_get_snapshot(self):
        _setup()
        token = issue_delegation_token(
            issuer_agent_id="agent-a",
            subject_agent_id="agent-b",
            delegated_scopes=["read", "write"],
            owner="owner-dev",
        )
        # Create snapshot
        r = client.post(
            f"/v1/chain-viz/tokens/{token['token_id']}/snapshot",
            headers=HEADERS,
        )
        assert r.status_code == 200
        snap = r.json()
        assert "snapshot_id" in snap
        assert snap["token_id"] == token["token_id"]
        assert "tree" in snap
        assert "risk" in snap

        # Get snapshot
        r2 = client.get(
            f"/v1/chain-viz/snapshots/{snap['snapshot_id']}",
            headers=HEADERS,
        )
        assert r2.status_code == 200
        assert r2.json()["snapshot_id"] == snap["snapshot_id"]

    def test_list_snapshots(self):
        _setup()
        token = issue_delegation_token(
            issuer_agent_id="agent-a",
            subject_agent_id="agent-b",
            delegated_scopes=["read"],
            owner="owner-dev",
        )
        client.post(
            f"/v1/chain-viz/tokens/{token['token_id']}/snapshot",
            headers=HEADERS,
        )
        r = client.get("/v1/chain-viz/snapshots", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data["count"] >= 1

    def test_snapshot_not_found(self):
        _setup()
        r = client.get(
            "/v1/chain-viz/snapshots/nonexistent",
            headers=HEADERS,
        )
        assert r.status_code == 404
