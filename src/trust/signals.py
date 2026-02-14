"""Multi-Signal Reputation Scoring v2 — enhanced trust with behavioral signals.

Extends the base reputation scoring with additional signal sources:
- Anomaly history (from behavioral anomaly detection)
- Policy compliance (from policy decision graph)
- Credential hygiene (rotation cadence, expiry management)
- Federation trust (cross-domain trust level)
- Peer attestations (from other agents)

Produces a composite trust signal that augments the base reputation score.
"""
from __future__ import annotations

import logging
import time
from typing import Any

_log = logging.getLogger("agenthub.trust_signals")

# Signal weights for v2 composite score
SIGNAL_WEIGHTS = {
    "anomaly_score": 0.25,       # From anomaly detection (inverted: low anomalies = high trust)
    "policy_compliance": 0.25,   # Allow rate in policy decisions
    "credential_hygiene": 0.20,  # Rotation discipline, no expired creds
    "federation_trust": 0.15,    # Cross-domain trust level
    "peer_attestation": 0.15,    # Attestations from other agents
}

# In-memory peer attestation store
_peer_attestations: list[dict[str, Any]] = []


def compute_anomaly_signal(agent_id: str) -> dict[str, Any]:
    """Compute trust signal from anomaly detection history."""
    from src.runtime.anomaly_detection import get_agent_risk_score

    risk = get_agent_risk_score(agent_id)
    risk_score = risk.get("risk_score", 0)
    # Invert: 0 risk = 1.0 trust, 100 risk = 0.0 trust
    trust_value = max(0.0, 1.0 - (risk_score / 100.0))

    return {
        "signal": "anomaly_score",
        "value": round(trust_value, 3),
        "risk_score": risk_score,
        "risk_level": risk.get("risk_level", "low"),
        "anomaly_count": risk.get("anomaly_count", 0),
    }


def compute_policy_compliance_signal(agent_id: str) -> dict[str, Any]:
    """Compute trust signal from policy decision compliance."""
    from src.policy.decision_graph import get_decisions_for_agent

    decisions = get_decisions_for_agent(agent_id, limit=100)
    if not decisions:
        return {
            "signal": "policy_compliance",
            "value": 0.5,  # Neutral with no data
            "total_decisions": 0,
            "allow_rate": 0.0,
        }

    allows = sum(1 for d in decisions if d.get("decision") == "allow")
    total = len(decisions)
    allow_rate = allows / total if total > 0 else 0.0

    return {
        "signal": "policy_compliance",
        "value": round(allow_rate, 3),
        "total_decisions": total,
        "allow_rate": round(allow_rate, 3),
        "deny_count": total - allows,
    }


def compute_credential_hygiene_signal(agent_id: str) -> dict[str, Any]:
    """Compute trust signal from credential management practices."""
    from src.identity.lifecycle import check_expiry_alerts, check_rotation_due

    expiry_alerts = check_expiry_alerts(agent_id)
    rotation_due = check_rotation_due(agent_id)

    # Penalties: expired creds reduce trust
    critical_alerts = [a for a in expiry_alerts if a.get("severity") == "critical"]
    warning_alerts = [a for a in expiry_alerts if a.get("severity") == "warning"]
    overdue_rotations = len(rotation_due)

    penalty = 0.0
    penalty += len(critical_alerts) * 0.3
    penalty += len(warning_alerts) * 0.1
    penalty += overdue_rotations * 0.15
    value = max(0.0, 1.0 - penalty)

    return {
        "signal": "credential_hygiene",
        "value": round(value, 3),
        "critical_alerts": len(critical_alerts),
        "warning_alerts": len(warning_alerts),
        "overdue_rotations": overdue_rotations,
    }


def compute_federation_trust_signal(agent_id: str) -> dict[str, Any]:
    """Compute trust signal from cross-domain federation status."""
    from src.federation.cross_domain import list_federation_agreements

    # Check if agent's domain has active federation agreements
    agreements = list_federation_agreements()
    active = [a for a in agreements if a.get("status") == "active"]

    if not active:
        return {
            "signal": "federation_trust",
            "value": 0.5,  # Neutral with no federation
            "active_agreements": 0,
        }

    # Higher trust levels = higher signal
    trust_levels = {"full": 1.0, "verified": 0.75, "limited": 0.5, "untrusted": 0.1}
    best_trust = max(trust_levels.get(a.get("trust_level", "untrusted"), 0.1) for a in active)

    return {
        "signal": "federation_trust",
        "value": round(best_trust, 3),
        "active_agreements": len(active),
        "best_trust_level": max((a.get("trust_level", "untrusted") for a in active), key=lambda t: trust_levels.get(t, 0)),
    }


def record_peer_attestation(
    *,
    attester_agent_id: str,
    subject_agent_id: str,
    attestation_type: str = "positive",
    confidence: float = 0.8,
    context: str = "",
) -> dict[str, Any]:
    """Record a peer attestation for an agent."""
    if attestation_type not in {"positive", "negative", "neutral"}:
        raise ValueError(f"invalid attestation type: {attestation_type}")
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0.0 and 1.0")
    if attester_agent_id == subject_agent_id:
        raise ValueError("self-attestation not allowed")

    now = time.time()
    attestation: dict[str, Any] = {
        "attester_agent_id": attester_agent_id,
        "subject_agent_id": subject_agent_id,
        "attestation_type": attestation_type,
        "confidence": round(confidence, 3),
        "context": context,
        "recorded_at": now,
    }
    _peer_attestations.append(attestation)
    return attestation


def compute_peer_attestation_signal(agent_id: str) -> dict[str, Any]:
    """Compute trust signal from peer attestations."""
    attestations = [a for a in _peer_attestations if a["subject_agent_id"] == agent_id]
    if not attestations:
        return {
            "signal": "peer_attestation",
            "value": 0.5,
            "attestation_count": 0,
        }

    type_values = {"positive": 1.0, "neutral": 0.5, "negative": 0.0}
    weighted_sum = 0.0
    weight_total = 0.0
    for a in attestations:
        val = type_values.get(a["attestation_type"], 0.5)
        w = a.get("confidence", 0.5)
        weighted_sum += val * w
        weight_total += w

    value = weighted_sum / weight_total if weight_total > 0 else 0.5

    positive = sum(1 for a in attestations if a["attestation_type"] == "positive")
    negative = sum(1 for a in attestations if a["attestation_type"] == "negative")

    return {
        "signal": "peer_attestation",
        "value": round(value, 3),
        "attestation_count": len(attestations),
        "positive": positive,
        "negative": negative,
    }


def compute_composite_trust_score(agent_id: str) -> dict[str, Any]:
    """Compute the v2 composite trust score from all signals."""
    signals = {
        "anomaly_score": compute_anomaly_signal(agent_id),
        "policy_compliance": compute_policy_compliance_signal(agent_id),
        "credential_hygiene": compute_credential_hygiene_signal(agent_id),
        "federation_trust": compute_federation_trust_signal(agent_id),
        "peer_attestation": compute_peer_attestation_signal(agent_id),
    }

    weighted_sum = 0.0
    for signal_name, weight in SIGNAL_WEIGHTS.items():
        signal_data = signals[signal_name]
        weighted_sum += signal_data["value"] * weight

    composite_score = round(weighted_sum * 100, 1)  # Scale to 0-100

    if composite_score >= 80:
        trust_tier = "high"
    elif composite_score >= 60:
        trust_tier = "moderate"
    elif composite_score >= 40:
        trust_tier = "low"
    else:
        trust_tier = "untrusted"

    return {
        "agent_id": agent_id,
        "composite_score": composite_score,
        "trust_tier": trust_tier,
        "signals": signals,
        "weights": SIGNAL_WEIGHTS,
        "computed_at": time.time(),
    }


def reset_for_tests() -> None:
    """Clear all signal data for testing."""
    _peer_attestations.clear()
