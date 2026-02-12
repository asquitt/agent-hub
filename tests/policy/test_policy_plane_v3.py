from __future__ import annotations

from src.policy import evaluate_delegation_policy, evaluate_install_promotion_policy, verify_decision_signature


def test_policy_decisions_are_signed_and_tamper_detectable() -> None:
    decision = evaluate_delegation_policy(
        actor="runtime.delegation",
        requester_agent_id="@demo:r",
        delegate_agent_id="@demo:d",
        estimated_cost_usd=2.0,
        max_budget_usd=10.0,
        auto_reauthorize=True,
        min_delegate_trust_score=0.5,
        delegate_trust_score=0.9,
        required_permissions=["records.read"],
        delegate_permissions=["records.read"],
        abac_context={
            "principal": {"tenant_id": "tenant-a", "allowed_actions": ["create_delegation"], "mfa_present": True},
            "resource": {"tenant_id": "tenant-a"},
            "environment": {"requires_mfa": False},
        },
    )
    assert decision["decision"] == "allow"
    assert verify_decision_signature(decision) is True

    tampered = dict(decision)
    tampered["decision"] = "deny"
    assert verify_decision_signature(tampered) is False


def test_abac_tenant_mismatch_denies_delegation() -> None:
    denied = evaluate_delegation_policy(
        actor="runtime.delegation",
        requester_agent_id="@demo:r",
        delegate_agent_id="@demo:d",
        estimated_cost_usd=1.0,
        max_budget_usd=10.0,
        auto_reauthorize=True,
        min_delegate_trust_score=0.5,
        delegate_trust_score=0.95,
        required_permissions=[],
        delegate_permissions=[],
        abac_context={
            "principal": {"tenant_id": "tenant-a", "allowed_actions": ["create_delegation"], "mfa_present": True},
            "resource": {"tenant_id": "tenant-b"},
            "environment": {"requires_mfa": False},
        },
    )
    assert denied["decision"] == "deny"
    assert "abac.tenant_mismatch" in denied["violated_constraints"]


def test_explainability_payload_contains_violation_codes() -> None:
    denied = evaluate_install_promotion_policy(
        actor="runtime.install",
        owner="owner-dev",
        lease_id="lease-1",
        policy_approved=False,
        attestation_hash="abc",
        signature="",
        abac_context={
            "principal": {"tenant_id": "tenant-a", "allowed_actions": ["promote_lease"], "mfa_present": False},
            "resource": {"tenant_id": "tenant-a"},
            "environment": {"requires_mfa": True},
        },
    )
    explainability = denied["explainability"]
    assert "approval.policy_required" in explainability["violation_codes"]
    assert "abac.mfa_required" in explainability["violation_codes"]
    assert verify_decision_signature(denied) is True
