"""Behavioral Anomaly Detection — detect abnormal agent behavior patterns.

Monitors agent activity and detects anomalies across dimensions:
- Frequency: unusual call rates (too high or too low)
- Scope: accessing resources outside normal patterns
- Timing: activity outside normal hours or in unusual patterns
- Volume: abnormal data volumes in tool calls
- Escalation: privilege escalation attempts
"""
from __future__ import annotations

import logging
import math
import time
from typing import Any

_log = logging.getLogger("agenthub.anomaly_detection")

# Anomaly severity levels
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"

# Detection dimensions
DIM_FREQUENCY = "frequency"
DIM_SCOPE = "scope"
DIM_TIMING = "timing"
DIM_VOLUME = "volume"
DIM_ESCALATION = "escalation"

# Default thresholds
DEFAULT_FREQUENCY_THRESHOLD = 100  # calls per minute
DEFAULT_VOLUME_THRESHOLD_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_BASELINE_WINDOW = 3600  # 1 hour

# In-memory stores
_activity_log: list[dict[str, Any]] = []
_baselines: dict[str, dict[str, Any]] = {}  # agent_id -> baseline metrics
_anomaly_log: list[dict[str, Any]] = []


def record_activity(
    *,
    agent_id: str,
    action: str,
    resource: str | None = None,
    data_bytes: int = 0,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record an agent activity event for anomaly baseline computation."""
    now = time.time()
    event = {
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "data_bytes": data_bytes,
        "metadata": metadata or {},
        "timestamp": now,
    }
    _activity_log.append(event)
    return event


def compute_baseline(
    agent_id: str,
    *,
    window_seconds: int = DEFAULT_BASELINE_WINDOW,
) -> dict[str, Any]:
    """Compute behavioral baseline for an agent from recent activity."""
    now = time.time()
    cutoff = now - window_seconds

    events = [e for e in _activity_log if e["agent_id"] == agent_id and e["timestamp"] >= cutoff]

    if not events:
        baseline = {
            "agent_id": agent_id,
            "event_count": 0,
            "avg_frequency_per_min": 0.0,
            "unique_resources": [],
            "unique_actions": [],
            "avg_data_bytes": 0.0,
            "stddev_data_bytes": 0.0,
            "computed_at": now,
            "window_seconds": window_seconds,
        }
        _baselines[agent_id] = baseline
        return baseline

    # Frequency
    time_span = max(now - events[0]["timestamp"], 60)  # At least 1 minute
    freq = len(events) / (time_span / 60)

    # Resources and actions
    resources = sorted({e["resource"] for e in events if e.get("resource")})
    actions = sorted({e["action"] for e in events})

    # Data volume stats
    bytes_list = [e.get("data_bytes", 0) for e in events]
    avg_bytes = sum(bytes_list) / len(bytes_list) if bytes_list else 0
    variance = sum((b - avg_bytes) ** 2 for b in bytes_list) / len(bytes_list) if len(bytes_list) > 1 else 0
    stddev_bytes = math.sqrt(variance)

    baseline = {
        "agent_id": agent_id,
        "event_count": len(events),
        "avg_frequency_per_min": round(freq, 2),
        "unique_resources": resources,
        "unique_actions": actions,
        "avg_data_bytes": round(avg_bytes, 2),
        "stddev_data_bytes": round(stddev_bytes, 2),
        "computed_at": now,
        "window_seconds": window_seconds,
    }
    _baselines[agent_id] = baseline
    return baseline


def detect_anomalies(
    agent_id: str,
    *,
    frequency_threshold: int = DEFAULT_FREQUENCY_THRESHOLD,
    volume_threshold_bytes: int = DEFAULT_VOLUME_THRESHOLD_BYTES,
    lookback_seconds: int = 60,
) -> dict[str, Any]:
    """Detect anomalies in an agent's recent behavior against its baseline."""
    now = time.time()
    baseline = _baselines.get(agent_id)
    if baseline is None:
        baseline = compute_baseline(agent_id)

    cutoff = now - lookback_seconds
    recent = [e for e in _activity_log if e["agent_id"] == agent_id and e["timestamp"] >= cutoff]

    anomalies: list[dict[str, Any]] = []

    # 1. Frequency anomaly
    current_freq = len(recent) / max(lookback_seconds / 60, 1)
    baseline_freq = baseline.get("avg_frequency_per_min", 0)
    if current_freq > frequency_threshold:
        anomalies.append({
            "dimension": DIM_FREQUENCY,
            "severity": SEVERITY_HIGH,
            "message": f"call rate {current_freq:.1f}/min exceeds threshold {frequency_threshold}/min",
            "current_value": round(current_freq, 2),
            "threshold": frequency_threshold,
        })
    elif baseline_freq > 0 and current_freq > baseline_freq * 3:
        anomalies.append({
            "dimension": DIM_FREQUENCY,
            "severity": SEVERITY_MEDIUM,
            "message": f"call rate {current_freq:.1f}/min is 3x baseline {baseline_freq:.1f}/min",
            "current_value": round(current_freq, 2),
            "baseline_value": baseline_freq,
        })

    # 2. Scope anomaly (new resources not in baseline)
    known_resources = set(baseline.get("unique_resources", []))
    recent_resources: set[str] = {e["resource"] for e in recent if e.get("resource")}
    new_resources = recent_resources - known_resources
    if new_resources and known_resources:  # Only flag if we have a baseline
        anomalies.append({
            "dimension": DIM_SCOPE,
            "severity": SEVERITY_MEDIUM,
            "message": f"accessing {len(new_resources)} new resource(s) not in baseline",
            "new_resources": sorted(new_resources),
        })

    # 3. Volume anomaly
    recent_bytes = [e.get("data_bytes", 0) for e in recent]
    max_bytes = max(recent_bytes) if recent_bytes else 0
    total_bytes = sum(recent_bytes)
    if max_bytes > volume_threshold_bytes:
        anomalies.append({
            "dimension": DIM_VOLUME,
            "severity": SEVERITY_HIGH,
            "message": f"single call transferred {max_bytes} bytes (threshold: {volume_threshold_bytes})",
            "max_bytes": max_bytes,
            "threshold": volume_threshold_bytes,
        })
    elif total_bytes > volume_threshold_bytes * 5:
        anomalies.append({
            "dimension": DIM_VOLUME,
            "severity": SEVERITY_MEDIUM,
            "message": f"total volume {total_bytes} bytes in {lookback_seconds}s window",
            "total_bytes": total_bytes,
        })

    # 4. Escalation (new actions not in baseline)
    known_actions = set(baseline.get("unique_actions", []))
    recent_actions = {e["action"] for e in recent}
    escalation_actions = {"admin", "delete", "revoke", "modify_policy", "grant_access"}
    new_escalation = (recent_actions & escalation_actions) - known_actions
    if new_escalation:
        anomalies.append({
            "dimension": DIM_ESCALATION,
            "severity": SEVERITY_CRITICAL,
            "message": f"new privileged actions detected: {sorted(new_escalation)}",
            "actions": sorted(new_escalation),
        })

    # Log anomalies
    for a in anomalies:
        record = {**a, "agent_id": agent_id, "detected_at": now}
        _anomaly_log.append(record)

    return {
        "agent_id": agent_id,
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "recent_event_count": len(recent),
        "baseline_event_count": baseline.get("event_count", 0),
        "checked_at": now,
    }


def get_anomaly_history(
    agent_id: str | None = None,
    *,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Get recent anomaly detections, optionally filtered by agent."""
    if agent_id:
        filtered = [a for a in _anomaly_log if a.get("agent_id") == agent_id]
    else:
        filtered = list(_anomaly_log)
    return filtered[-limit:]


def get_agent_risk_score(agent_id: str) -> dict[str, Any]:
    """Compute a risk score (0-100) for an agent based on anomaly history."""
    agent_anomalies = [a for a in _anomaly_log if a.get("agent_id") == agent_id]

    if not agent_anomalies:
        return {"agent_id": agent_id, "risk_score": 0, "risk_level": "low", "anomaly_count": 0}

    severity_weights = {SEVERITY_LOW: 5, SEVERITY_MEDIUM: 15, SEVERITY_HIGH: 30, SEVERITY_CRITICAL: 50}
    total_weight = sum(severity_weights.get(a.get("severity", ""), 5) for a in agent_anomalies)

    # Cap at 100
    score = min(total_weight, 100)

    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"

    return {
        "agent_id": agent_id,
        "risk_score": score,
        "risk_level": level,
        "anomaly_count": len(agent_anomalies),
    }


def reset_for_tests() -> None:
    """Clear all stores for testing."""
    _activity_log.clear()
    _baselines.clear()
    _anomaly_log.clear()
