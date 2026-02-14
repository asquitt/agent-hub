"""Intent-Aware Access Logging — capture why agents perform actions.

Records access events enriched with declared intent, enabling:
- Audit trails with business justification
- Intent drift detection (stated intent vs actual behavior)
- Policy decisions based on intent classification
- Compliance evidence with purpose limitation
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.intent_logging")

# Intent categories
INTENT_DATA_ACCESS = "data_access"
INTENT_ADMINISTRATION = "administration"
INTENT_DELEGATION = "delegation"
INTENT_INTEGRATION = "integration"
INTENT_MONITORING = "monitoring"
INTENT_COMPLIANCE = "compliance"
INTENT_UNKNOWN = "unknown"

VALID_INTENTS = {
    INTENT_DATA_ACCESS, INTENT_ADMINISTRATION, INTENT_DELEGATION,
    INTENT_INTEGRATION, INTENT_MONITORING, INTENT_COMPLIANCE, INTENT_UNKNOWN,
}

# Risk scoring by intent
INTENT_RISK: dict[str, int] = {
    INTENT_DATA_ACCESS: 20,
    INTENT_ADMINISTRATION: 60,
    INTENT_DELEGATION: 50,
    INTENT_INTEGRATION: 30,
    INTENT_MONITORING: 10,
    INTENT_COMPLIANCE: 10,
    INTENT_UNKNOWN: 40,
}

# In-memory stores
_MAX_RECORDS = 10_000
_access_log: list[dict[str, Any]] = []
_intent_policies: dict[str, dict[str, Any]] = {}  # policy_id -> policy


def log_access(
    *,
    agent_id: str,
    action: str,
    resource: str | None = None,
    intent: str = INTENT_UNKNOWN,
    justification: str = "",
    outcome: str = "allowed",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Log an access event with intent information."""
    if intent not in VALID_INTENTS:
        intent = INTENT_UNKNOWN

    now = time.time()
    entry_id = f"access-{uuid.uuid4().hex[:12]}"

    risk_score = INTENT_RISK.get(intent, 40)
    # Intent-action drift detection
    drift = _detect_drift(agent_id=agent_id, action=action, intent=intent)

    entry: dict[str, Any] = {
        "entry_id": entry_id,
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "intent": intent,
        "justification": justification,
        "outcome": outcome,
        "risk_score": risk_score,
        "drift_detected": drift is not None,
        "drift_detail": drift,
        "metadata": metadata or {},
        "timestamp": now,
    }

    _access_log.append(entry)
    if len(_access_log) > _MAX_RECORDS:
        _access_log[:] = _access_log[-_MAX_RECORDS:]

    if drift:
        _log.warning(
            "intent drift: agent=%s action=%s intent=%s drift=%s",
            agent_id, action, intent, drift,
        )

    return entry


def query_access_log(
    *,
    agent_id: str | None = None,
    intent: str | None = None,
    action: str | None = None,
    outcome: str | None = None,
    since: float | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Query the access log with filters."""
    results: list[dict[str, Any]] = []
    for entry in reversed(_access_log):
        if agent_id and entry["agent_id"] != agent_id:
            continue
        if intent and entry["intent"] != intent:
            continue
        if action and entry["action"] != action:
            continue
        if outcome and entry["outcome"] != outcome:
            continue
        if since and entry["timestamp"] < since:
            continue
        results.append(entry)
        if len(results) >= limit:
            break
    return results


def get_intent_summary(agent_id: str) -> dict[str, Any]:
    """Summarize an agent's declared intents and drift patterns."""
    entries = [e for e in _access_log if e["agent_id"] == agent_id]
    if not entries:
        return {
            "agent_id": agent_id,
            "total_events": 0,
            "intent_distribution": {},
            "drift_count": 0,
            "avg_risk_score": 0,
        }

    intent_counts: dict[str, int] = {}
    drift_count = 0
    risk_sum = 0

    for e in entries:
        intent_counts[e["intent"]] = intent_counts.get(e["intent"], 0) + 1
        if e.get("drift_detected"):
            drift_count += 1
        risk_sum += e.get("risk_score", 0)

    return {
        "agent_id": agent_id,
        "total_events": len(entries),
        "intent_distribution": intent_counts,
        "drift_count": drift_count,
        "drift_rate": round(drift_count / len(entries), 3) if entries else 0,
        "avg_risk_score": round(risk_sum / len(entries), 1) if entries else 0,
    }


def set_intent_policy(
    *,
    policy_id: str | None = None,
    agent_id: str | None = None,
    allowed_intents: list[str] | None = None,
    required_justification: bool = False,
    max_risk_score: int = 100,
) -> dict[str, Any]:
    """Set an intent policy for access control."""
    pid = policy_id or f"intent-pol-{uuid.uuid4().hex[:8]}"
    policy: dict[str, Any] = {
        "policy_id": pid,
        "agent_id": agent_id,
        "allowed_intents": allowed_intents or list(VALID_INTENTS),
        "required_justification": required_justification,
        "max_risk_score": max_risk_score,
        "created_at": time.time(),
    }
    _intent_policies[pid] = policy
    if len(_intent_policies) > _MAX_RECORDS:
        oldest = sorted(_intent_policies, key=lambda k: _intent_policies[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _intent_policies[k]
    return policy


def evaluate_intent(
    *,
    agent_id: str,
    intent: str,
    justification: str = "",
) -> dict[str, Any]:
    """Evaluate whether an intent is allowed by policy."""
    risk = INTENT_RISK.get(intent, 40)

    for policy in _intent_policies.values():
        if policy.get("agent_id") and policy["agent_id"] != agent_id:
            continue
        allowed = policy.get("allowed_intents", list(VALID_INTENTS))
        if intent not in allowed:
            return {
                "allowed": False,
                "reason": f"intent '{intent}' not in allowed intents",
                "policy_id": policy["policy_id"],
            }
        if policy.get("required_justification") and not justification:
            return {
                "allowed": False,
                "reason": "justification required by policy",
                "policy_id": policy["policy_id"],
            }
        if risk > policy.get("max_risk_score", 100):
            return {
                "allowed": False,
                "reason": f"risk score {risk} exceeds max {policy['max_risk_score']}",
                "policy_id": policy["policy_id"],
            }

    return {"allowed": True, "reason": "no policy violation", "risk_score": risk}


def list_intent_policies() -> list[dict[str, Any]]:
    """List all intent policies."""
    return list(_intent_policies.values())


def _detect_drift(*, agent_id: str, action: str, intent: str) -> str | None:
    """Detect if the declared intent doesn't match the action pattern."""
    action_lower = action.lower()

    # Administration intent but read action
    if intent == INTENT_ADMINISTRATION and "read" in action_lower:
        return "admin intent but read-only action"

    # Data access intent but admin action
    if intent == INTENT_DATA_ACCESS and any(
        k in action_lower for k in ("admin", "delete", "revoke", "modify_policy")
    ):
        return "data_access intent but privileged action"

    # Monitoring intent but write action
    if intent == INTENT_MONITORING and any(
        k in action_lower for k in ("write", "create", "delete", "update")
    ):
        return "monitoring intent but write action"

    return None


def reset_for_tests() -> None:
    """Clear all intent logging data for testing."""
    _access_log.clear()
    _intent_policies.clear()
