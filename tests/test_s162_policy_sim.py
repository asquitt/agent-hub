"""Tests for S162 — Policy simulation (what-if analysis)."""
from __future__ import annotations

import os
os.environ.setdefault("AGENTHUB_API_KEYS_JSON", '{"dev-owner-key":"owner-dev"}')
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-secret")
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-identity-secret")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", '{"test-domain":"test-token"}')
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-provenance-secret")
os.environ.setdefault("AGENTHUB_POLICY_SIGNING_SECRET", "test-policy-secret")

from fastapi.testclient import TestClient

from src.api.app import app
from src.policy.policy_as_code import create_rule, reset_for_tests as reset_rules
from src.runtime.policy_sim import _reset as reset_sim

client = TestClient(app)
HEADERS = {"X-API-Key": "dev-owner-key", "X-Idempotency-Key": "test-sim"}


def _setup() -> None:
    reset_rules()
    reset_sim()


class TestSimulateAccess:
    def test_simulate_with_no_rules(self):
        _setup()
        r = client.post(
            "/v1/policy-sim/access",
            json={
                "agent_id": "agent-a",
                "actions": ["read", "write", "delete"],
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["summary"]["total"] == 3
        # Default allow when no rules
        assert data["summary"]["allowed"] == 3

    def test_simulate_with_deny_rule(self):
        _setup()
        create_rule(
            name="deny-delete",
            effect="deny",
            target_actions=["delete"],
        )
        r = client.post(
            "/v1/policy-sim/access",
            json={
                "agent_id": "agent-a",
                "actions": ["read", "delete"],
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["summary"]["denied"] >= 1

    def test_simulate_missing_params(self):
        _setup()
        r = client.post(
            "/v1/policy-sim/access",
            json={"agent_id": "agent-a"},
            headers=HEADERS,
        )
        assert r.status_code == 422


class TestSimulateRuleChange:
    def test_add_rule_changes_decisions(self):
        _setup()
        # No rules: all should be allowed
        r = client.post(
            "/v1/policy-sim/rule-change",
            json={
                "rule_changes": [
                    {
                        "action": "add",
                        "rule": {
                            "name": "deny-write",
                            "effect": "deny",
                            "target_actions": ["write"],
                            "priority": 200,
                        },
                    }
                ],
                "test_cases": [
                    {"agent_id": "agent-a", "action": "write"},
                    {"agent_id": "agent-b", "action": "read"},
                ],
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert "simulation_id" in data
        assert data["impact_summary"]["total_test_cases"] == 2
        # Write action should change from allow to deny
        assert data["impact_summary"]["decisions_changed"] >= 1
        # Before state: both allowed
        assert data["before_results"][0]["decision"] == "allow"
        # After state: write denied
        assert data["after_results"][0]["decision"] == "deny"
        # Read should still be allowed
        assert data["after_results"][1]["decision"] == "allow"

    def test_disable_existing_rule(self):
        _setup()
        rule = create_rule(
            name="deny-all-delete",
            effect="deny",
            target_actions=["delete"],
        )
        r = client.post(
            "/v1/policy-sim/rule-change",
            json={
                "rule_changes": [
                    {
                        "action": "disable",
                        "rule": {"rule_id": rule["rule_id"]},
                    }
                ],
                "test_cases": [
                    {"agent_id": "agent-a", "action": "delete"},
                ],
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        # Before: denied, After: allowed
        assert data["before_results"][0]["decision"] == "deny"
        assert data["after_results"][0]["decision"] == "allow"

    def test_rules_restored_after_simulation(self):
        """Verify hypothetical changes don't persist."""
        _setup()
        r = client.post(
            "/v1/policy-sim/rule-change",
            json={
                "rule_changes": [
                    {
                        "action": "add",
                        "rule": {
                            "name": "temp-deny",
                            "effect": "deny",
                            "target_actions": ["*"],
                        },
                    }
                ],
                "test_cases": [
                    {"agent_id": "agent-a", "action": "read"},
                ],
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        # Now the actual evaluate should still allow (no persistent rule)
        r2 = client.post(
            "/v1/policy-sim/access",
            json={
                "agent_id": "agent-a",
                "actions": ["read"],
            },
            headers=HEADERS,
        )
        assert r2.status_code == 200
        assert r2.json()["summary"]["allowed"] == 1


class TestImpactAnalysis:
    def test_impact_across_agents(self):
        _setup()
        create_rule(
            name="deny-agent-b-write",
            effect="deny",
            target_agents=["agent-b"],
            target_actions=["write"],
        )
        r = client.post(
            "/v1/policy-sim/impact",
            json={
                "agent_ids": ["agent-a", "agent-b", "agent-c"],
                "action": "write",
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["total_agents"] == 3
        assert data["summary"]["denied"] >= 1
        assert data["summary"]["allowed"] >= 1


class TestSimulationHistory:
    def test_list_and_get_simulation(self):
        _setup()
        # Run a simulation to create one
        r = client.post(
            "/v1/policy-sim/rule-change",
            json={
                "rule_changes": [{"action": "add", "rule": {"name": "test", "effect": "deny", "target_actions": ["x"]}}],
                "test_cases": [{"agent_id": "a", "action": "x"}],
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        sim_id = r.json()["simulation_id"]

        # List simulations
        r2 = client.get("/v1/policy-sim/simulations", headers=HEADERS)
        assert r2.status_code == 200
        assert r2.json()["count"] >= 1

        # Get specific simulation
        r3 = client.get(f"/v1/policy-sim/simulations/{sim_id}", headers=HEADERS)
        assert r3.status_code == 200
        assert r3.json()["simulation_id"] == sim_id

    def test_simulation_not_found(self):
        _setup()
        r = client.get("/v1/policy-sim/simulations/nonexistent", headers=HEADERS)
        assert r.status_code == 404
