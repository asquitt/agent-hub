from __future__ import annotations

from src.api.auth import AuthContext
from src.policy.mcp_relay import evaluate_mcp_relay_policy


def _target() -> dict:
    return {
        "target_id": "catalog",
        "tenant_id": "tenant-a",
        "endpoint_digest": "endpoint",
        "tool_name": "lookup",
        "max_call_cost_usd": 0.1,
        "operator_attests_read_only": True,
        "policy_revision": "policy",
        "enabled": True,
    }


def _context(method: str = "jwt_bearer") -> AuthContext:
    return AuthContext(
        "owner-a",
        scopes=["relay.call"],
        roles=["member"],
        tenant_id="tenant-a",
        auth_method=method,  # type: ignore[arg-type]
        agent_id=None if method == "api_key" else "agent-a",
    )


def test_relay_policy_allows_exact_live_agent_capability() -> None:
    target = _target()
    decision = evaluate_mcp_relay_policy(
        actor=_context(),
        target=target,
        configured_target=target,
        capability={
            "valid": True,
            "token_id": "cap-a",
            "subject": "agent-a",
            "effective_scopes": ["mcp.tools.lookup.invoke"],
        },
        required_scope="mcp.tools.lookup.invoke",
    )
    assert decision["allowed"] is True


def test_relay_policy_denies_api_key_config_drift_and_wrong_subject() -> None:
    target = _target()
    configured = {**target, "endpoint_digest": "changed"}
    decision = evaluate_mcp_relay_policy(
        actor=_context("api_key"),
        target=target,
        configured_target=configured,
        capability={
            "valid": True,
            "token_id": "cap-a",
            "subject": "agent-b",
            "effective_scopes": ["mcp.tools.lookup.invoke"],
        },
        required_scope="mcp.tools.lookup.invoke",
    )
    assert decision["allowed"] is False
    assert set(decision["violated_constraints"]) == {
        "relay.agent_required",
        "relay.auth_method_denied",
        "relay.configuration_drift",
    }
