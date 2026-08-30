from __future__ import annotations

from typing import Any, Protocol

from src.policy.helpers import build_decision, reason

RELAY_POLICY_VERSION = "mcp-relay-policy-v1"
ALLOWED_RELAY_AUTH_METHODS = frozenset(
    {"agent_credential", "jwt_bearer", "delegation_token"}
)


class RelayAuthContext(Protocol):
    @property
    def owner(self) -> str: ...

    @property
    def tenant_id(self) -> str: ...

    @property
    def agent_id(self) -> str | None: ...

    @property
    def auth_method(self) -> str: ...

    def allows_scope(self, required_scope: str) -> bool: ...


def evaluate_mcp_relay_policy(
    *,
    actor: RelayAuthContext,
    target: dict[str, Any],
    configured_target: dict[str, Any],
    capability: dict[str, Any],
    required_scope: str,
) -> dict[str, Any]:
    reasons: list[dict[str, Any]] = []

    if actor.auth_method not in ALLOWED_RELAY_AUTH_METHODS:
        reasons.append(
            reason(
                "relay.auth_method_denied",
                "relay calls require a revocation-aware agent principal",
                "violation",
                field="auth_method",
                expected=sorted(ALLOWED_RELAY_AUTH_METHODS),
                observed=actor.auth_method,
            )
        )
    if actor.agent_id is None:
        reasons.append(
            reason(
                "relay.agent_required",
                "relay calls require an agent-bound principal",
                "violation",
                field="agent_id",
                expected="non-empty",
                observed=None,
            )
        )
    if not actor.allows_scope("relay.call"):
        reasons.append(
            reason(
                "relay.principal_scope_denied",
                "authenticated principal lacks relay.call scope",
                "violation",
                field="principal.scopes",
                expected="relay.call",
            )
        )
    if actor.tenant_id != target.get("tenant_id"):
        reasons.append(
            reason(
                "relay.tenant_mismatch",
                "relay target is not available in the authenticated tenant",
                "violation",
                field="tenant_id",
                expected=target.get("tenant_id"),
                observed=actor.tenant_id,
            )
        )
    if not bool(target.get("enabled")):
        reasons.append(
            reason("relay.target_disabled", "relay target is disabled", "violation")
        )

    drift_fields = [
        field
        for field in (
            "endpoint_digest",
            "tool_name",
            "tenant_id",
            "max_call_cost_usd",
            "operator_attests_read_only",
        )
        if target.get(field) != configured_target.get(field)
    ]
    if drift_fields:
        reasons.append(
            reason(
                "relay.configuration_drift",
                "persisted relay target differs from the operator allowlist",
                "violation",
                field="target",
                expected="exact configured target",
                observed=sorted(drift_fields),
            )
        )
    if target.get("operator_attests_read_only") is not True:
        reasons.append(
            reason(
                "relay.operator_attestation_missing",
                "operator read-only attestation is missing",
                "violation",
            )
        )

    if not bool(capability.get("valid")):
        reasons.append(
            reason(
                "relay.capability_denied",
                str(capability.get("reason", "capability verification failed")),
                "violation",
            )
        )
    if actor.agent_id is not None and capability.get("subject") != actor.agent_id:
        reasons.append(
            reason(
                "relay.capability_subject_mismatch",
                "capability subject does not match the authenticated agent",
                "violation",
                field="capability.subject",
                expected=actor.agent_id,
                observed=capability.get("subject"),
            )
        )
    effective_scopes = capability.get("effective_scopes", [])
    if required_scope not in effective_scopes:
        reasons.append(
            reason(
                "relay.capability_scope_denied",
                "capability does not authorize this exact MCP tool",
                "violation",
                field="capability.effective_scopes",
                expected=required_scope,
                observed=effective_scopes,
            )
        )
    if not reasons:
        reasons.append(
            reason(
                "relay.policy_allow",
                "configured target and live capability authorize one read-only call",
                "allow",
            )
        )

    return build_decision(
        context=RELAY_POLICY_VERSION,
        action="mcp.tools.call",
        actor=actor.owner,
        subject={
            "agent_id": actor.agent_id,
            "target_id": target.get("target_id"),
            "tool_name": target.get("tool_name"),
            "capability_token_id": capability.get("token_id"),
        },
        evaluated_constraints={
            "auth_method": actor.auth_method,
            "tenant_id": actor.tenant_id,
            "target_enabled": bool(target.get("enabled")),
            "target_policy_revision": target.get("policy_revision"),
            "configured_policy_revision": configured_target.get("policy_revision"),
            "required_scope": required_scope,
            "operator_attests_read_only": bool(
                target.get("operator_attests_read_only")
            ),
            "configuration_drift_fields": sorted(drift_fields),
        },
        reasons=reasons,
    )
