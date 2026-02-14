"""ABAC (Attribute-Based Access Control) violation checks."""
from __future__ import annotations

from typing import Any

from src.policy.helpers import reason


def abac_violations(
    *,
    action: str,
    abac_context: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if not abac_context:
        return []

    reasons: list[dict[str, Any]] = []
    principal = abac_context.get("principal", {}) if isinstance(abac_context, dict) else {}
    resource = abac_context.get("resource", {}) if isinstance(abac_context, dict) else {}
    environment = abac_context.get("environment", {}) if isinstance(abac_context, dict) else {}
    principal = principal if isinstance(principal, dict) else {}
    resource = resource if isinstance(resource, dict) else {}
    environment = environment if isinstance(environment, dict) else {}

    principal_tenant = principal.get("tenant_id")
    resource_tenant = resource.get("tenant_id")
    if principal_tenant and resource_tenant and str(principal_tenant) != str(resource_tenant):
        reasons.append(
            reason(
                "abac.tenant_mismatch",
                "principal and resource tenant boundaries do not match",
                "violation",
                field="abac_context.tenant_id",
                expected=resource_tenant,
                observed=principal_tenant,
            )
        )

    allowed_actions = principal.get("allowed_actions")
    if isinstance(allowed_actions, list) and allowed_actions:
        allowed = {str(item) for item in allowed_actions}
        if action not in allowed and "*" not in allowed:
            reasons.append(
                reason(
                    "abac.action_not_allowed",
                    "principal is not authorized for requested action",
                    "violation",
                    field="abac_context.principal.allowed_actions",
                    expected=sorted(allowed),
                    observed=action,
                )
            )

    if bool(environment.get("requires_mfa")) and not bool(principal.get("mfa_present")):
        reasons.append(
            reason(
                "abac.mfa_required",
                "principal must satisfy MFA requirement for this action",
                "violation",
                field="abac_context.environment.requires_mfa",
                expected=True,
                observed=bool(principal.get("mfa_present")),
            )
        )

    return reasons
