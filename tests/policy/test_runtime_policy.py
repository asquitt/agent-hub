from __future__ import annotations

from src.policy import (
    evaluate_delegation_policy,
    evaluate_discovery_policy,
    evaluate_install_promotion_policy,
)


def test_discovery_policy_is_deterministic() -> None:
    request_constraints = {
        "min_trust_score": 0.8,
        "max_cost_usd": 0.05,
        "required_permissions": ["records.read"],
        "allowed_protocols": ["MCP"],
    }
    first = evaluate_discovery_policy(
        action="semantic_search",
        actor="runtime.discovery",
        query="extract invoice totals",
        constraints=request_constraints,
    )
    second = evaluate_discovery_policy(
        action="semantic_search",
        actor="runtime.discovery",
        query="extract invoice totals",
        constraints=request_constraints,
    )
    assert first == second
    assert first["decision"] == "allow"
    assert first["violated_constraints"] == []


def test_discovery_policy_denies_invalid_constraints() -> None:
    report = evaluate_discovery_policy(
        action="semantic_search",
        actor="runtime.discovery",
        query="ok",
        constraints={
            "required_permissions": ["payments.*"],
            "allowed_protocols": ["SOAP"],
        },
    )
    assert report["decision"] == "deny"
    assert "permissions.invalid_required_permission" in report["violated_constraints"]
    assert "protocol.unsupported_protocol" in report["violated_constraints"]


def test_delegation_policy_budget_and_permission_boundaries() -> None:
    allow_with_soft_alert = evaluate_delegation_policy(
        actor="runtime.delegation",
        requester_agent_id="@demo:r",
        delegate_agent_id="@demo:d",
        estimated_cost_usd=8.0,
        max_budget_usd=10.0,
        auto_reauthorize=True,
        min_delegate_trust_score=0.8,
        delegate_trust_score=0.85,
        required_permissions=["records.read"],
        delegate_permissions=["records.read", "records.write"],
    )
    assert allow_with_soft_alert["decision"] == "allow"
    assert any(r["code"] == "budget.soft_alert_80" for r in allow_with_soft_alert["reasons"])

    deny_for_reauth = evaluate_delegation_policy(
        actor="runtime.delegation",
        requester_agent_id="@demo:r",
        delegate_agent_id="@demo:d",
        estimated_cost_usd=10.0,
        max_budget_usd=10.0,
        auto_reauthorize=False,
        min_delegate_trust_score=0.8,
        delegate_trust_score=0.85,
        required_permissions=["records.read"],
        delegate_permissions=["records.read"],
    )
    assert deny_for_reauth["decision"] == "deny"
    assert "budget.reauthorization_required_100" in deny_for_reauth["violated_constraints"]

    deny_for_permissions = evaluate_delegation_policy(
        actor="runtime.delegation",
        requester_agent_id="@demo:r",
        delegate_agent_id="@demo:d",
        estimated_cost_usd=4.0,
        max_budget_usd=10.0,
        auto_reauthorize=True,
        min_delegate_trust_score=0.9,
        delegate_trust_score=0.82,
        required_permissions=["payments.execute"],
        delegate_permissions=["records.read"],
    )
    assert deny_for_permissions["decision"] == "deny"
    assert "permissions.missing_required" in deny_for_permissions["violated_constraints"]
    assert "trust.floor_not_met" in deny_for_permissions["violated_constraints"]


def test_install_promotion_policy_requires_explicit_approval() -> None:
    denied = evaluate_install_promotion_policy(
        actor="runtime.install",
        owner="owner-dev",
        lease_id="lease-1",
        policy_approved=False,
        attestation_hash="12345",
        signature="",
    )
    assert denied["decision"] == "deny"
    assert "approval.policy_required" in denied["violated_constraints"]

    allowed = evaluate_install_promotion_policy(
        actor="runtime.install",
        owner="owner-dev",
        lease_id="lease-1",
        policy_approved=True,
        attestation_hash="a" * 64,
        signature="sig:a",
    )
    assert allowed["decision"] == "allow"
