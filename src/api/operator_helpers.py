from __future__ import annotations

from typing import Any

from fastapi import HTTPException


OPERATOR_ROLE_BY_OWNER = {
    "owner-dev": "admin",
    "owner-platform": "admin",
    "owner-partner": "viewer",
}


def resolve_operator_role(owner: str, requested_role: str | None) -> str:
    assigned = OPERATOR_ROLE_BY_OWNER.get(owner, "viewer")
    if requested_role is None:
        return assigned
    if requested_role not in {"viewer", "admin"}:
        raise HTTPException(status_code=403, detail="invalid operator role")
    if requested_role == "admin" and assigned != "admin":
        raise HTTPException(status_code=403, detail="insufficient operator role")
    return requested_role


def require_operator_role(owner: str, requested_role: str | None, allowed_roles: set[str]) -> str:
    role = resolve_operator_role(owner, requested_role)
    if role not in allowed_roles:
        raise HTTPException(status_code=403, detail="operator role not permitted")
    return role


def delegation_timeline(delegations: list[dict[str, Any]], limit: int = 60) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in delegations:
        delegation_id = str(row.get("delegation_id", ""))
        for stage in row.get("lifecycle", []):
            if not isinstance(stage, dict):
                continue
            events.append(
                {
                    "timestamp": stage.get("timestamp"),
                    "delegation_id": delegation_id,
                    "event_type": "lifecycle_stage",
                    "event_name": stage.get("stage"),
                    "details": stage.get("details", {}),
                }
            )
        for audit in row.get("audit_trail", []):
            if not isinstance(audit, dict):
                continue
            events.append(
                {
                    "timestamp": audit.get("timestamp"),
                    "delegation_id": delegation_id,
                    "event_type": "audit",
                    "event_name": audit.get("type", "audit"),
                    "details": audit.get("details", {}),
                }
            )

    events.sort(key=lambda item: str(item.get("timestamp", "")), reverse=True)
    return events[:limit]


def policy_cost_overlay(delegations: list[dict[str, Any]]) -> dict[str, Any]:
    estimated_total = 0.0
    actual_total = 0.0
    hard_stop_count = 0
    pending_reauth_count = 0
    soft_alert_count = 0

    cards: list[dict[str, Any]] = []
    for row in delegations:
        estimated = float(row.get("estimated_cost_usd", 0.0) or 0.0)
        actual = float(row.get("actual_cost_usd", 0.0) or 0.0)
        estimated_total += estimated
        actual_total += actual

        status = str(row.get("status", "unknown"))
        if status == "failed_hard_stop":
            hard_stop_count += 1
        if status == "pending_reauthorization":
            pending_reauth_count += 1
        budget_controls = row.get("budget_controls", {}) if isinstance(row.get("budget_controls"), dict) else {}
        if bool(budget_controls.get("soft_alert")):
            soft_alert_count += 1

        policy_decision = row.get("policy_decision", {}) if isinstance(row.get("policy_decision"), dict) else {}
        cards.append(
            {
                "delegation_id": row.get("delegation_id"),
                "status": status,
                "updated_at": row.get("updated_at"),
                "estimated_cost_usd": round(estimated, 6),
                "actual_cost_usd": round(actual, 6),
                "budget_ratio": float(budget_controls.get("ratio", 0.0) or 0.0),
                "budget_state": budget_controls.get("state", "unknown"),
                "policy_decision": policy_decision.get("decision", "unknown"),
            }
        )

    cards.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)
    return {
        "totals": {
            "estimated_cost_usd": round(estimated_total, 6),
            "actual_cost_usd": round(actual_total, 6),
            "delegation_count": len(delegations),
            "hard_stop_count": hard_stop_count,
            "pending_reauthorization_count": pending_reauth_count,
            "soft_alert_count": soft_alert_count,
        },
        "delegation_cards": cards[:8],
    }
