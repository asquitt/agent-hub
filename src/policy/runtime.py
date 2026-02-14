from __future__ import annotations

import hashlib
import json
import os
import string
from typing import Any

POLICY_VERSION = "runtime-policy-v3"
SUPPORTED_PROTOCOLS = {"MCP", "A2A", "HTTP", "INTERNAL"}


def _stable_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _policy_signing_secret() -> bytes:
    secret = os.getenv("AGENTHUB_POLICY_SIGNING_SECRET", "agenthub-policy-signing-secret")
    return secret.encode("utf-8")


def _sign_policy_payload(payload: dict[str, Any]) -> str:
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(_policy_signing_secret() + normalized).hexdigest()


def _reason(
    code: str,
    message: str,
    reason_type: str,
    *,
    field: str | None = None,
    expected: Any | None = None,
    observed: Any | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "code": code,
        "message": message,
        "type": reason_type,
    }
    if field is not None:
        row["field"] = field
    if expected is not None:
        row["expected"] = expected
    if observed is not None:
        row["observed"] = observed
    return row


def _abac_violations(
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
            _reason(
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
                _reason(
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
            _reason(
                "abac.mfa_required",
                "principal must satisfy MFA requirement for this action",
                "violation",
                field="abac_context.environment.requires_mfa",
                expected=True,
                observed=bool(principal.get("mfa_present")),
            )
        )

    return reasons


def _build_decision(
    context: str,
    action: str,
    actor: str,
    subject: dict[str, Any],
    evaluated_constraints: dict[str, Any],
    reasons: list[dict[str, Any]],
) -> dict[str, Any]:
    ordered_reasons = sorted(
        reasons,
        key=lambda row: (
            row.get("type", ""),
            row.get("code", ""),
            row.get("field", ""),
            str(row.get("observed", "")),
            str(row.get("expected", "")),
        ),
    )
    violated_constraints = sorted({row["code"] for row in ordered_reasons if row.get("type") == "violation"})
    allowed = not violated_constraints
    payload = {
        "context": context,
        "action": action,
        "actor": actor,
        "subject": subject,
        "evaluated_constraints": evaluated_constraints,
        "reasons": ordered_reasons,
        "violated_constraints": violated_constraints,
        "policy_version": POLICY_VERSION,
    }
    input_hash = _stable_hash(payload)
    decision_id = _stable_hash({"policy_version": POLICY_VERSION, "input_hash": input_hash})[:24]
    explainability = {
        "violation_codes": [row["code"] for row in ordered_reasons if row.get("type") == "violation"],
        "warning_codes": [row["code"] for row in ordered_reasons if row.get("type") == "warning"],
        "allow_codes": [row["code"] for row in ordered_reasons if row.get("type") == "allow"],
        "evaluated_fields": sorted(evaluated_constraints.keys()),
    }
    signature_payload = {
        "policy_version": POLICY_VERSION,
        "decision_id": decision_id,
        "context": context,
        "action": action,
        "actor": actor,
        "subject": subject,
        "decision": "allow" if allowed else "deny",
        "violated_constraints": violated_constraints,
        "input_hash": input_hash,
    }
    decision_signature = _sign_policy_payload(signature_payload)
    return {
        "policy_version": POLICY_VERSION,
        "decision_id": decision_id,
        "context": context,
        "action": action,
        "actor": actor,
        "subject": subject,
        "decision": "allow" if allowed else "deny",
        "allowed": allowed,
        "reasons": ordered_reasons,
        "violated_constraints": violated_constraints,
        "evaluated_constraints": evaluated_constraints,
        "input_hash": input_hash,
        "explainability": explainability,
        "signature_algorithm": "sha256(secret+payload)",
        "decision_signature": decision_signature,
    }


def verify_decision_signature(decision: dict[str, Any]) -> bool:
    if not isinstance(decision, dict):
        return False
    required = {
        "policy_version",
        "decision_id",
        "context",
        "action",
        "actor",
        "subject",
        "decision",
        "violated_constraints",
        "input_hash",
        "decision_signature",
    }
    if not required.issubset(decision.keys()):
        return False
    payload = {
        "policy_version": decision["policy_version"],
        "decision_id": decision["decision_id"],
        "context": decision["context"],
        "action": decision["action"],
        "actor": decision["actor"],
        "subject": decision["subject"],
        "decision": decision["decision"],
        "violated_constraints": decision["violated_constraints"],
        "input_hash": decision["input_hash"],
    }
    expected = _sign_policy_payload(payload)
    return str(decision.get("decision_signature", "")) == expected


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
            _reason(
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
                _reason(
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
                _reason(
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
            _reason(
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
                    _reason(
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
            _reason(
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
                    _reason(
                        "protocol.unsupported_protocol",
                        "unsupported protocol in allowed_protocols",
                        "violation",
                        field="constraints.allowed_protocols",
                        expected=sorted(SUPPORTED_PROTOCOLS),
                        observed=protocol,
                    )
                )

    reasons.extend(_abac_violations(action=action, abac_context=abac_context))

    if not reasons:
        reasons.append(_reason("policy.allow", "discovery policy checks passed", "allow"))

    return _build_decision(
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
            _reason(
                "contract.input_required_empty",
                "input_required must not be empty",
                "violation",
                field="input_required",
            )
        )
    if not output_required:
        reasons.append(
            _reason(
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
                    _reason(
                        "contract.required_field_invalid",
                        "required field names must be non-empty strings",
                        "violation",
                        field=field_name,
                        observed=value,
                    )
                )

    reasons.extend(_abac_violations(action="contract_match", abac_context=abac_context))

    if not reasons:
        reasons.append(_reason("policy.allow", "contract-match policy checks passed", "allow"))

    return _build_decision(
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
            _reason(
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
                    _reason(
                        "compat.required_entry_invalid",
                        "required entries must be non-empty strings",
                        "violation",
                        field="my_schema.required",
                        observed=value,
                    )
                )

    if not isinstance(agent_id, str) or agent_id.strip() == "":
        reasons.append(
            _reason(
                "compat.agent_id_invalid",
                "agent_id must be non-empty",
                "violation",
                field="agent_id",
            )
        )

    reasons.extend(_abac_violations(action="compatibility", abac_context=abac_context))

    if not reasons:
        reasons.append(_reason("policy.allow", "compatibility policy checks passed", "allow"))

    return _build_decision(
        context="discovery",
        action="compatibility",
        actor=actor,
        subject={"agent_id": agent_id},
        evaluated_constraints={"required": required if isinstance(required, list) else []},
        reasons=reasons,
    )


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
            _reason(
                "budget.max_budget_invalid",
                "max_budget_usd must be > 0",
                "violation",
                field="max_budget_usd",
                observed=max_budget_usd,
            )
        )

    if estimated_cost_usd <= 0:
        reasons.append(
            _reason(
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
            _reason(
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
            _reason(
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
            _reason(
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
                _reason(
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
                _reason(
                    "trust.delegate_score_missing",
                    "delegate trust score required when min_delegate_trust_score is set",
                    "violation",
                    field="delegate_trust_score",
                )
            )
        elif delegate_trust_score < float(min_delegate_trust_score):
            reasons.append(
                _reason(
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
            _reason(
                "permissions.missing_required",
                "delegate does not satisfy required permissions",
                "violation",
                field="required_permissions",
                expected=sorted(required),
                observed=sorted(delegate_allowed),
            )
        )

    reasons.extend(_abac_violations(action="create_delegation", abac_context=abac_context))

    if not reasons:
        reasons.append(_reason("policy.allow", "delegation policy checks passed", "allow"))

    return _build_decision(
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


def evaluate_install_promotion_policy(
    *,
    actor: str,
    owner: str,
    lease_id: str,
    policy_approved: bool,
    attestation_hash: str,
    signature: str,
    abac_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reasons: list[dict[str, Any]] = []

    if not policy_approved:
        reasons.append(
            _reason(
                "approval.policy_required",
                "explicit policy approval is required for install promotion",
                "violation",
                field="policy_approved",
                expected=True,
                observed=False,
            )
        )

    if not isinstance(attestation_hash, str) or len(attestation_hash) < 12:
        reasons.append(
            _reason(
                "attestation.hash_invalid",
                "attestation hash must be a non-empty hash string",
                "violation",
                field="attestation_hash",
                expected="len>=12",
                observed=len(attestation_hash) if isinstance(attestation_hash, str) else None,
            )
        )
    elif any(ch not in string.hexdigits for ch in attestation_hash):
        reasons.append(
            _reason(
                "attestation.hash_not_hex",
                "attestation hash must be hexadecimal",
                "violation",
                field="attestation_hash",
            )
        )

    if not isinstance(signature, str) or signature.strip() == "":
        reasons.append(
            _reason(
                "attestation.signature_missing",
                "attestation signature is required",
                "violation",
                field="signature",
            )
        )

    reasons.extend(_abac_violations(action="promote_lease", abac_context=abac_context))

    if not reasons:
        reasons.append(_reason("policy.allow", "install promotion policy checks passed", "allow"))

    return _build_decision(
        context="install",
        action="promote_lease",
        actor=actor,
        subject={"owner": owner, "lease_id": lease_id},
        evaluated_constraints={
            "policy_approved": policy_approved,
            "attestation_hash_prefix": attestation_hash[:12] if isinstance(attestation_hash, str) else "",
        },
        reasons=reasons,
    )


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
            _reason(
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
                _reason(
                    "identity.scope_insufficient",
                    f"credential lacks required scope: {required_scope}",
                    "violation",
                    field="credential_scopes",
                    expected=required_scope,
                    observed=sorted(credential_scopes),
                )
            )

    reasons.extend(_abac_violations(action=action, abac_context=abac_context))

    if not reasons:
        reasons.append(_reason("policy.allow", "agent credential policy checks passed", "allow"))

    return _build_decision(
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
            _reason(
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
                _reason(
                    "delegation.scope_insufficient",
                    f"delegation token lacks required scope: {required_scope}",
                    "violation",
                    field="delegated_scopes",
                    expected=required_scope,
                    observed=sorted(delegated_scopes),
                )
            )

    reasons.extend(_abac_violations(action=action, abac_context=abac_context))

    if not reasons:
        reasons.append(_reason("policy.allow", "delegation token policy checks passed", "allow"))

    return _build_decision(
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
