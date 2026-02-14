"""Activity Monitor — Real-time agent activity tracking.

Tracks agent actions (API calls, resource access, delegation events)
with anomaly flagging and activity summaries.
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.activity_monitor")

_MAX_RECORDS = 10_000
_activities: dict[str, dict[str, Any]] = {}  # activity_id -> record
_alerts: dict[str, dict[str, Any]] = {}  # alert_id -> alert


def record_activity(
    *,
    agent_id: str,
    action: str,
    resource: str | None = None,
    details: dict[str, Any] | None = None,
    source_ip: str | None = None,
) -> dict[str, Any]:
    """Record an agent activity event."""
    aid = f"act-{uuid.uuid4().hex[:12]}"
    now = time.time()

    record: dict[str, Any] = {
        "activity_id": aid,
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "details": details or {},
        "source_ip": source_ip,
        "timestamp": now,
    }

    _activities[aid] = record

    # Check for anomalies
    _check_anomalies(record)

    if len(_activities) > _MAX_RECORDS:
        oldest = sorted(_activities, key=lambda k: _activities[k]["timestamp"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _activities[k]

    return record


def get_activity(activity_id: str) -> dict[str, Any]:
    """Get a specific activity record."""
    rec = _activities.get(activity_id)
    if not rec:
        raise KeyError(f"activity not found: {activity_id}")
    return rec


def list_activities(
    *,
    agent_id: str | None = None,
    action: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List activity records with optional filters."""
    results: list[dict[str, Any]] = []
    for rec in sorted(_activities.values(), key=lambda r: r["timestamp"], reverse=True):
        if agent_id and rec["agent_id"] != agent_id:
            continue
        if action and rec["action"] != action:
            continue
        results.append(rec)
        if len(results) >= limit:
            break
    return results


def get_agent_summary(agent_id: str) -> dict[str, Any]:
    """Get activity summary for an agent."""
    agent_acts = [r for r in _activities.values() if r["agent_id"] == agent_id]
    if not agent_acts:
        return {
            "agent_id": agent_id,
            "total_activities": 0,
            "actions": {},
            "first_seen": None,
            "last_seen": None,
        }

    actions: dict[str, int] = {}
    for r in agent_acts:
        actions[r["action"]] = actions.get(r["action"], 0) + 1

    timestamps = [r["timestamp"] for r in agent_acts]
    return {
        "agent_id": agent_id,
        "total_activities": len(agent_acts),
        "actions": actions,
        "first_seen": min(timestamps),
        "last_seen": max(timestamps),
        "unique_resources": len({r["resource"] for r in agent_acts if r["resource"]}),
        "unique_ips": len({r["source_ip"] for r in agent_acts if r["source_ip"]}),
    }


def create_alert(
    *,
    agent_id: str,
    alert_type: str,
    severity: str,
    message: str,
    activity_id: str | None = None,
) -> dict[str, Any]:
    """Create a manual alert for suspicious activity."""
    valid_severities = {"low", "medium", "high", "critical"}
    if severity not in valid_severities:
        raise ValueError(f"severity must be one of {valid_severities}")

    alert_id = f"alert-{uuid.uuid4().hex[:12]}"
    now = time.time()

    alert: dict[str, Any] = {
        "alert_id": alert_id,
        "agent_id": agent_id,
        "alert_type": alert_type,
        "severity": severity,
        "message": message,
        "activity_id": activity_id,
        "status": "open",
        "created_at": now,
    }

    _alerts[alert_id] = alert

    if len(_alerts) > _MAX_RECORDS:
        oldest = sorted(_alerts, key=lambda k: _alerts[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _alerts[k]

    return alert


def get_alert(alert_id: str) -> dict[str, Any]:
    """Get a specific alert."""
    alert = _alerts.get(alert_id)
    if not alert:
        raise KeyError(f"alert not found: {alert_id}")
    return alert


def list_alerts(
    *,
    agent_id: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List alerts with optional filters."""
    results: list[dict[str, Any]] = []
    for alert in sorted(_alerts.values(), key=lambda a: a["created_at"], reverse=True):
        if agent_id and alert["agent_id"] != agent_id:
            continue
        if status and alert["status"] != status:
            continue
        if severity and alert["severity"] != severity:
            continue
        results.append(alert)
        if len(results) >= limit:
            break
    return results


def acknowledge_alert(alert_id: str) -> dict[str, Any]:
    """Acknowledge an alert."""
    alert = _alerts.get(alert_id)
    if not alert:
        raise KeyError(f"alert not found: {alert_id}")
    alert["status"] = "acknowledged"
    alert["acknowledged_at"] = time.time()
    return alert


def get_activity_stats() -> dict[str, Any]:
    """Get activity monitoring statistics."""
    total = len(_activities)
    agents = {r["agent_id"] for r in _activities.values()}
    actions: dict[str, int] = {}
    for r in _activities.values():
        actions[r["action"]] = actions.get(r["action"], 0) + 1

    total_alerts = len(_alerts)
    open_alerts = sum(1 for a in _alerts.values() if a["status"] == "open")

    return {
        "total_activities": total,
        "unique_agents": len(agents),
        "action_breakdown": actions,
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "acknowledged_alerts": total_alerts - open_alerts,
    }


# ── Internal helpers ─────────────────────────────────────────────────

# Configurable thresholds for anomaly detection
_RATE_WINDOW = 60.0  # seconds
_RATE_THRESHOLD = 50  # max actions per window per agent


def _check_anomalies(record: dict[str, Any]) -> None:
    """Check for anomalous activity and auto-create alerts."""
    agent_id = record["agent_id"]
    now = record["timestamp"]

    # Rate spike detection
    recent = [
        r for r in _activities.values()
        if r["agent_id"] == agent_id and now - r["timestamp"] < _RATE_WINDOW
    ]
    if len(recent) > _RATE_THRESHOLD:
        create_alert(
            agent_id=agent_id,
            alert_type="rate_spike",
            severity="high",
            message=f"Agent {agent_id} exceeded {_RATE_THRESHOLD} actions in {_RATE_WINDOW}s",
            activity_id=record["activity_id"],
        )


def reset_for_tests() -> None:
    """Clear all activity data for testing."""
    _activities.clear()
    _alerts.clear()
