"""Discovery, contract-match, and compatibility policy evaluators."""
from __future__ import annotations

from typing import Any

from src.policy.abac import abac_violations
from src.policy.helpers import SUPPORTED_PROTOCOLS, build_decision, reason


def evaluate_discovery_policy(
    *,
    action: str,
    actor: str,
    query: str,
    constraints: dict[str, Any] | None,
    abac_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    constraints = constraints or {}
    reasons: list[dict[str, Any]] = []
    query_size = len(query.strip())
    if query_size < 2:
        reasons.append(
            reason(
                "discovery.query_too_short",
                "query must be at least 2 non-whitespace characters",
                "violation",
                field="query",
                expected="len>=2",
                observed=query_size,
            )
        )

    if "min_trust_score" in constraints:
        trust = constraints["min_trust_score"]
        if not isinstance(trust, (int, float)) or trust < 0 or trust > 1:
            reasons.append(
                reason(
                    "trust.floor_out_of_range",
                    "min_trust_score must be in [0,1]",
                    "violation",
                    field="constraints.min_trust_score",
                    expected="[0,1]",
                    observed=trust,
                )
            )

    if "max_cost_usd" in constraints:
        max_cost = constraints["max_cost_usd"]
        if not isinstance(max_cost, (int, float)) or max_cost < 0:
            reasons.append(
                reason(
                    "budget.max_cost_invalid",
                    "max_cost_usd must be a non-negative number",
                    "violation",
                    field="constraints.max_cost_usd",
                    expected=">=0",
                    observed=max_cost,
                )
            )

    required_permissions = constraints.get("required_permissions", [])
    if required_permissions is not None and not isinstance(required_permissions, list):
        reasons.append(
            reason(
                "permissions.required_permissions_type_invalid",
                "required_permissions must be an array of strings",
                "violation",
                field="constraints.required_permissions",
                expected="list[str]",
                observed=type(required_permissions).__name__,
            )
        )
    elif isinstance(required_permissions, list):
        for permission in required_permissions:
            if not isinstance(permission, str) or permission.strip() == "" or "*" in permission:
                reasons.append(
                    reason(
                        "permissions.invalid_required_permission",
                        "required permission entries must be non-empty strings without wildcards",
                        "violation",
                        field="constraints.required_permissions",
                        observed=permission,
                    )
                )

    protocols = constraints.get("allowed_protocols", [])
    if protocols is not None and not isinstance(protocols, list):
        reasons.append(
            reason(
                "protocol.allowed_protocols_type_invalid",
                "allowed_protocols must be an array of protocol names",
                "violation",
                field="constraints.allowed_protocols",
                expected="list[str]",
                observed=type(protocols).__name__,
            )
        )
    elif isinstance(protocols, list):
        for protocol in protocols:
            if protocol not in SUPPORTED_PROTOCOLS:
                reasons.append(
                    reason(
                        "protocol.unsupported_protocol",
                        "unsupported protocol in allowed_protocols",
                        "violation",
                        field="constraints.allowed_protocols",
                        expected=sorted(SUPPORTED_PROTOCOLS),
                        observed=protocol,
                    )
                )

    reasons.extend(abac_violations(action=action, abac_context=abac_context))

    if not reasons:
        reasons.append(reason("policy.allow", "discovery policy checks passed", "allow"))

    return build_decision(
        context="discovery",
        action=action,
        actor=actor,
        subject={"query": query},
        evaluated_constraints=constraints,
        reasons=reasons,
    )


def evaluate_contract_match_policy(
    *,
    actor: str,
    input_required: list[str],
    output_required: list[str],
    constraints: dict[str, Any] | None,
    abac_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    constraints = constraints or {}
    reasons: list[dict[str, Any]] = []

    if not input_required:
        reasons.append(
            reason(
                "contract.input_required_empty",
                "input_required must not be empty",
                "violation",
                field="input_required",
            )
        )
    if not output_required:
        reasons.append(
            reason(
                "contract.output_required_empty",
                "output_required must not be empty",
                "violation",
                field="output_required",
            )
        )

    for field_name, values in (("input_required", input_required), ("output_required", output_required)):
        for value in values:
            if not isinstance(value, str) or value.strip() == "":
                reasons.append(
                    reason(
                        "contract.required_field_invalid",
                        "required field names must be non-empty strings",
                        "violation",
                        field=field_name,
                        observed=value,
                    )
                )

    reasons.extend(abac_violations(action="contract_match", abac_context=abac_context))

    if not reasons:
        reasons.append(reason("policy.allow", "contract-match policy checks passed", "allow"))

    return build_decision(
        context="discovery",
        action="contract_match",
        actor=actor,
        subject={"input_required": sorted(input_required), "output_required": sorted(output_required)},
        evaluated_constraints=constraints,
        reasons=reasons,
    )


def evaluate_compatibility_policy(
    *,
    actor: str,
    my_schema: dict[str, Any],
    agent_id: str,
    abac_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reasons: list[dict[str, Any]] = []
    required = my_schema.get("required", [])
    if not isinstance(required, list):
        reasons.append(
            reason(
                "compat.required_type_invalid",
                "my_schema.required must be an array",
                "violation",
                field="my_schema.required",
                expected="list[str]",
                observed=type(required).__name__,
            )
        )
    else:
        for value in required:
            if not isinstance(value, str) or value.strip() == "":
                reasons.append(
                    reason(
                        "compat.required_entry_invalid",
                        "required entries must be non-empty strings",
                        "violation",
                        field="my_schema.required",
                        observed=value,
                    )
                )

    if not isinstance(agent_id, str) or agent_id.strip() == "":
        reasons.append(
            reason(
                "compat.agent_id_invalid",
                "agent_id must be non-empty",
                "violation",
                field="agent_id",
            )
        )

    reasons.extend(abac_violations(action="compatibility", abac_context=abac_context))

    if not reasons:
        reasons.append(reason("policy.allow", "compatibility policy checks passed", "allow"))

    return build_decision(
        context="discovery",
        action="compatibility",
        actor=actor,
        subject={"agent_id": agent_id},
        evaluated_constraints={"required": required if isinstance(required, list) else []},
        reasons=reasons,
    )
