"""Agent credential and delegation token policy evaluators."""
from __future__ import annotations

from typing import Any

from src.policy.abac import abac_violations
from src.policy.helpers import build_decision, reason


def evaluate_agent_credential_policy(
    *,
    action: str,
    actor: str,
    agent_id: str,
    credential_scopes: list[str],
    required_scope: str | None = None,
    agent_status: str = "active",
    abac_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate whether an agent credential is authorized for an action."""
    reasons: list[dict[str, Any]] = []

    if agent_status != "active":
        reasons.append(
            reason(
                "identity.agent_not_active",
                f"agent identity status is {agent_status}",
                "violation",
                field="agent_status",
                expected="active",
                observed=agent_status,
            )
        )

    if required_scope is not None:
        has_wildcard = "*" in credential_scopes
        if not has_wildcard and required_scope not in credential_scopes:
            reasons.append(
                reason(
                    "identity.scope_insufficient",
                    f"credential lacks required scope: {required_scope}",
                    "violation",
                    field="credential_scopes",
                    expected=required_scope,
                    observed=sorted(credential_scopes),
                )
            )

    reasons.extend(abac_violations(action=action, abac_context=abac_context))

    if not reasons:
        reasons.append(reason("policy.allow", "agent credential policy checks passed", "allow"))

    return build_decision(
        context="identity",
        action=action,
        actor=actor,
        subject={"agent_id": agent_id},
        evaluated_constraints={
            "agent_status": agent_status,
            "credential_scopes": sorted(credential_scopes),
            "required_scope": required_scope,
            "abac_context_present": bool(abac_context),
        },
        reasons=reasons,
    )


def evaluate_delegation_token_policy(
    *,
    action: str,
    actor: str,
    issuer_agent_id: str,
    subject_agent_id: str,
    delegated_scopes: list[str],
    chain_depth: int,
    max_chain_depth: int = 5,
    required_scope: str | None = None,
    abac_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate whether a delegation token is authorized for an action."""
    reasons: list[dict[str, Any]] = []

    if chain_depth >= max_chain_depth:
        reasons.append(
            reason(
                "delegation.chain_depth_exceeded",
                f"delegation chain depth {chain_depth} exceeds maximum {max_chain_depth}",
                "violation",
                field="chain_depth",
                expected=f"<{max_chain_depth}",
                observed=chain_depth,
            )
        )

    if required_scope is not None:
        has_wildcard = "*" in delegated_scopes
        if not has_wildcard and required_scope not in delegated_scopes:
            reasons.append(
                reason(
                    "delegation.scope_insufficient",
                    f"delegation token lacks required scope: {required_scope}",
                    "violation",
                    field="delegated_scopes",
                    expected=required_scope,
                    observed=sorted(delegated_scopes),
                )
            )

    reasons.extend(abac_violations(action=action, abac_context=abac_context))

    if not reasons:
        reasons.append(reason("policy.allow", "delegation token policy checks passed", "allow"))

    return build_decision(
        context="delegation_token",
        action=action,
        actor=actor,
        subject={
            "issuer_agent_id": issuer_agent_id,
            "subject_agent_id": subject_agent_id,
        },
        evaluated_constraints={
            "chain_depth": chain_depth,
            "max_chain_depth": max_chain_depth,
            "delegated_scopes": sorted(delegated_scopes),
            "required_scope": required_scope,
            "abac_context_present": bool(abac_context),
        },
        reasons=reasons,
    )
