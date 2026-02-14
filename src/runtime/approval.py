"""Human-in-the-Loop Approval Workflows — approval gates for agent operations.

Implements approval workflows for sensitive agent actions:
- Request creation with configurable policies (auto-approve, require-approval, deny)
- Approval/rejection with audit trail
- Timeout-based auto-expiry
- Webhook-style notification hooks (URL stored, caller dispatches)
- Policy engine integration for auto-decisions
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.approval")

# Request states
STATE_PENDING = "pending"
STATE_APPROVED = "approved"
STATE_REJECTED = "rejected"
STATE_EXPIRED = "expired"
STATE_AUTO_APPROVED = "auto_approved"

# Action risk levels
RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"
RISK_CRITICAL = "critical"

# Default policies by risk level
DEFAULT_POLICIES: dict[str, str] = {
    RISK_LOW: "auto_approve",
    RISK_MEDIUM: "auto_approve",
    RISK_HIGH: "require_approval",
    RISK_CRITICAL: "require_approval",
}

# Well-known action categories
ACTION_CATEGORIES: dict[str, str] = {
    "delete": RISK_HIGH,
    "revoke": RISK_HIGH,
    "admin": RISK_CRITICAL,
    "grant_access": RISK_HIGH,
    "modify_policy": RISK_CRITICAL,
    "execute": RISK_MEDIUM,
    "read": RISK_LOW,
    "write": RISK_MEDIUM,
    "create": RISK_LOW,
    "deploy": RISK_HIGH,
    "transfer": RISK_HIGH,
}

# In-memory stores
_MAX_RECORDS = 10_000
_approval_requests: dict[str, dict[str, Any]] = {}  # request_id -> request
_approval_policies: dict[str, dict[str, Any]] = {}  # policy_id -> policy
_notification_hooks: list[dict[str, Any]] = []


def classify_risk(action: str) -> str:
    """Classify the risk level of an action."""
    action_lower = action.lower()
    for keyword, risk in ACTION_CATEGORIES.items():
        if keyword in action_lower:
            return risk
    return RISK_MEDIUM


def create_approval_request(
    *,
    agent_id: str,
    action: str,
    resource: str | None = None,
    justification: str = "",
    metadata: dict[str, Any] | None = None,
    ttl_seconds: int = 3600,
) -> dict[str, Any]:
    """Create an approval request for a sensitive action."""
    request_id = f"approval-{uuid.uuid4().hex[:12]}"
    now = time.time()
    risk = classify_risk(action)
    policy_decision = _evaluate_policy(agent_id=agent_id, action=action, risk=risk)

    request: dict[str, Any] = {
        "request_id": request_id,
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "justification": justification,
        "metadata": metadata or {},
        "risk_level": risk,
        "status": STATE_PENDING,
        "policy_decision": policy_decision,
        "created_at": now,
        "expires_at": now + ttl_seconds,
        "decided_at": None,
        "decided_by": None,
        "decision_reason": None,
    }

    # Auto-approve if policy says so
    if policy_decision == "auto_approve":
        request["status"] = STATE_AUTO_APPROVED
        request["decided_at"] = now
        request["decided_by"] = "policy_engine"
        request["decision_reason"] = f"auto-approved: risk={risk}"
        _log.info("auto-approved: %s action=%s risk=%s", request_id, action, risk)

    _approval_requests[request_id] = request
    if len(_approval_requests) > _MAX_RECORDS:
        oldest = sorted(_approval_requests, key=lambda k: _approval_requests[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _approval_requests[k]

    # Store notification hook metadata
    if request["status"] == STATE_PENDING:
        _notification_hooks.append({
            "type": "approval_requested",
            "request_id": request_id,
            "agent_id": agent_id,
            "action": action,
            "risk_level": risk,
            "timestamp": now,
        })
        if len(_notification_hooks) > _MAX_RECORDS:
            _notification_hooks[:] = _notification_hooks[-_MAX_RECORDS:]

    return request


def decide_approval(
    *,
    request_id: str,
    decision: str,
    decided_by: str,
    reason: str = "",
) -> dict[str, Any]:
    """Approve or reject a pending request."""
    request = _approval_requests.get(request_id)
    if request is None:
        raise KeyError(f"approval request not found: {request_id}")

    if decision not in {"approve", "reject"}:
        raise ValueError(f"invalid decision: {decision}")

    now = time.time()

    # Check if expired
    if request["status"] == STATE_PENDING and now > request["expires_at"]:
        request["status"] = STATE_EXPIRED
        raise ValueError("approval request has expired")

    if request["status"] != STATE_PENDING:
        raise ValueError(f"request is {request['status']}, cannot decide")

    request["status"] = STATE_APPROVED if decision == "approve" else STATE_REJECTED
    request["decided_at"] = now
    request["decided_by"] = decided_by
    request["decision_reason"] = reason

    _log.info(
        "approval decided: %s decision=%s by=%s",
        request_id, decision, decided_by,
    )
    return request


def get_approval_request(request_id: str) -> dict[str, Any]:
    """Get an approval request by ID."""
    request = _approval_requests.get(request_id)
    if request is None:
        raise KeyError(f"approval request not found: {request_id}")

    # Auto-expire
    if request["status"] == STATE_PENDING and time.time() > request["expires_at"]:
        request["status"] = STATE_EXPIRED

    return request


def list_approval_requests(
    *,
    agent_id: str | None = None,
    status: str | None = None,
    risk_level: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List approval requests with optional filters."""
    now = time.time()
    results: list[dict[str, Any]] = []

    for req in _approval_requests.values():
        # Auto-expire
        if req["status"] == STATE_PENDING and now > req["expires_at"]:
            req["status"] = STATE_EXPIRED

        if agent_id and req["agent_id"] != agent_id:
            continue
        if status and req["status"] != status:
            continue
        if risk_level and req["risk_level"] != risk_level:
            continue

        results.append({
            "request_id": req["request_id"],
            "agent_id": req["agent_id"],
            "action": req["action"],
            "resource": req["resource"],
            "risk_level": req["risk_level"],
            "status": req["status"],
            "created_at": req["created_at"],
            "decided_at": req["decided_at"],
            "decided_by": req["decided_by"],
        })
        if len(results) >= limit:
            break

    return results


def check_approval(
    *,
    agent_id: str,
    action: str,
    resource: str | None = None,
) -> dict[str, Any]:
    """Check if an action is pre-approved or needs approval."""
    risk = classify_risk(action)
    policy = _evaluate_policy(agent_id=agent_id, action=action, risk=risk)

    if policy == "auto_approve":
        return {
            "approved": True,
            "reason": f"auto-approved by policy (risk={risk})",
            "requires_request": False,
        }
    if policy == "deny":
        return {
            "approved": False,
            "reason": f"denied by policy (risk={risk})",
            "requires_request": False,
        }

    # Check for existing approved request
    now = time.time()
    for req in _approval_requests.values():
        if (
            req["agent_id"] == agent_id
            and req["action"] == action
            and req.get("resource") == resource
            and req["status"] in {STATE_APPROVED, STATE_AUTO_APPROVED}
            and req["expires_at"] > now
        ):
            return {
                "approved": True,
                "reason": f"approved via request {req['request_id']}",
                "requires_request": False,
                "request_id": req["request_id"],
            }

    return {
        "approved": False,
        "reason": f"requires human approval (risk={risk})",
        "requires_request": True,
        "risk_level": risk,
    }


def set_approval_policy(
    *,
    policy_id: str | None = None,
    agent_id: str | None = None,
    action_pattern: str | None = None,
    risk_level: str | None = None,
    decision: str,
) -> dict[str, Any]:
    """Set an approval policy rule."""
    if decision not in {"auto_approve", "require_approval", "deny"}:
        raise ValueError(f"invalid decision: {decision}")

    pid = policy_id or f"policy-{uuid.uuid4().hex[:8]}"
    policy: dict[str, Any] = {
        "policy_id": pid,
        "agent_id": agent_id,
        "action_pattern": action_pattern,
        "risk_level": risk_level,
        "decision": decision,
        "created_at": time.time(),
    }
    _approval_policies[pid] = policy
    if len(_approval_policies) > _MAX_RECORDS:
        oldest = sorted(_approval_policies, key=lambda k: _approval_policies[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _approval_policies[k]
    return policy


def list_approval_policies() -> list[dict[str, Any]]:
    """List all approval policies."""
    return list(_approval_policies.values())


def _evaluate_policy(*, agent_id: str, action: str, risk: str) -> str:
    """Evaluate policies to determine approval decision."""
    # Check agent-specific + action-specific policies first
    for p in _approval_policies.values():
        if p.get("agent_id") and p["agent_id"] != agent_id:
            continue
        if p.get("action_pattern") and p["action_pattern"] not in action:
            continue
        if p.get("risk_level") and p["risk_level"] != risk:
            continue
        return str(p["decision"])

    # Fall back to defaults
    return DEFAULT_POLICIES.get(risk, "require_approval")


def get_pending_count(agent_id: str | None = None) -> dict[str, Any]:
    """Get count of pending approval requests."""
    now = time.time()
    pending = 0
    total = 0
    for req in _approval_requests.values():
        if req["status"] == STATE_PENDING and now > req["expires_at"]:
            req["status"] = STATE_EXPIRED
        if agent_id and req["agent_id"] != agent_id:
            continue
        total += 1
        if req["status"] == STATE_PENDING:
            pending += 1

    return {"pending": pending, "total": total, "agent_id": agent_id}


def reset_for_tests() -> None:
    """Clear all approval data for testing."""
    _approval_requests.clear()
    _approval_policies.clear()
    _notification_hooks.clear()
