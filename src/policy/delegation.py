"""Delegation policy evaluator."""
from __future__ import annotations

from typing import Any

from src.policy.abac import abac_violations
from src.policy.helpers import build_decision, reason


def evaluate_delegation_policy(
    *,
    actor: str,
    requester_agent_id: str,
    delegate_agent_id: str,
    estimated_cost_usd: float,
    max_budget_usd: float,
    auto_reauthorize: bool,
    min_delegate_trust_score: float | None,
    delegate_trust_score: float | None,
    required_permissions: list[str],
    delegate_permissions: list[str],
    abac_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reasons: list[dict[str, Any]] = []

    if max_budget_usd <= 0:
        reasons.append(
            reason(
                "budget.max_budget_invalid",
                "max_budget_usd must be > 0",
                "violation",
                field="max_budget_usd",
                observed=max_budget_usd,
            )
        )

    if estimated_cost_usd <= 0:
        reasons.append(
            reason(
                "budget.estimated_cost_invalid",
                "estimated_cost_usd must be > 0",
                "violation",
                field="estimated_cost_usd",
                observed=estimated_cost_usd,
            )
        )

    ratio = estimated_cost_usd / max(max_budget_usd, 0.000001)
    if ratio >= 1.2:
        reasons.append(
            reason(
                "budget.hard_stop_120",
                "estimated cost exceeds hard-stop threshold (120%)",
                "violation",
                field="estimated_cost_usd",
                expected="<1.2x max_budget_usd",
                observed=round(ratio, 6),
            )
        )
    elif ratio >= 1.0 and not auto_reauthorize:
        reasons.append(
            reason(
                "budget.reauthorization_required_100",
                "estimated cost reached re-authorization threshold and auto_reauthorize is disabled",
                "violation",
                field="auto_reauthorize",
                expected=True,
                observed=auto_reauthorize,
            )
        )
    elif ratio >= 0.8:
        reasons.append(
            reason(
                "budget.soft_alert_80",
                "estimated cost crossed soft-alert threshold (80%)",
                "warning",
                field="estimated_cost_usd",
                observed=round(ratio, 6),
            )
        )

    if min_delegate_trust_score is not None:
        if not isinstance(min_delegate_trust_score, (int, float)) or min_delegate_trust_score < 0 or min_delegate_trust_score > 1:
            reasons.append(
                reason(
                    "trust.floor_out_of_range",
                    "min_delegate_trust_score must be in [0,1]",
                    "violation",
                    field="min_delegate_trust_score",
                    expected="[0,1]",
                    observed=min_delegate_trust_score,
                )
            )
        elif delegate_trust_score is None:
            reasons.append(
                reason(
                    "trust.delegate_score_missing",
                    "delegate trust score required when min_delegate_trust_score is set",
                    "violation",
                    field="delegate_trust_score",
                )
            )
        elif delegate_trust_score < float(min_delegate_trust_score):
            reasons.append(
                reason(
                    "trust.floor_not_met",
                    "delegate trust score below required minimum",
                    "violation",
                    field="min_delegate_trust_score",
                    expected=float(min_delegate_trust_score),
                    observed=float(delegate_trust_score),
                )
            )

    required = {perm for perm in required_permissions if isinstance(perm, str) and perm.strip()}
    delegate_allowed = {perm for perm in delegate_permissions if isinstance(perm, str) and perm.strip()}
    missing_permissions = sorted(required - delegate_allowed)
    if missing_permissions:
        reasons.append(
            reason(
                "permissions.missing_required",
                "delegate does not satisfy required permissions",
                "violation",
                field="required_permissions",
                expected=sorted(required),
                observed=sorted(delegate_allowed),
            )
        )

    reasons.extend(abac_violations(action="create_delegation", abac_context=abac_context))

    if not reasons:
        reasons.append(reason("policy.allow", "delegation policy checks passed", "allow"))

    return build_decision(
        context="delegation",
        action="create_delegation",
        actor=actor,
        subject={"requester_agent_id": requester_agent_id, "delegate_agent_id": delegate_agent_id},
        evaluated_constraints={
            "estimated_cost_usd": estimated_cost_usd,
            "max_budget_usd": max_budget_usd,
            "budget_ratio": round(ratio, 6),
            "auto_reauthorize": auto_reauthorize,
            "min_delegate_trust_score": min_delegate_trust_score,
            "delegate_trust_score": delegate_trust_score,
            "required_permissions": sorted(required),
            "delegate_permissions": sorted(delegate_allowed),
            "abac_context_present": bool(abac_context),
        },
        reasons=reasons,
    )
