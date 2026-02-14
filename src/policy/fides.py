"""FIDES Information-Flow Control — label lattice with taint tracking.

Implements a Bell-LaPadula inspired model adapted for agent systems:
- Confidentiality labels (top-secret > secret > confidential > public)
- Integrity labels (critical > high > medium > low)
- Label assignment to resources and agents
- Flow validation: data can only flow from lower to equal/higher confidentiality,
  and from higher to equal/lower integrity ("no read up, no write down")
- Taint tracking: tracks information flow chains with propagation
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.fides")

# Confidentiality levels (ascending order)
CONFIDENTIALITY_LEVELS = ["public", "confidential", "secret", "top-secret"]
CONFIDENTIALITY_RANK = {level: i for i, level in enumerate(CONFIDENTIALITY_LEVELS)}

# Integrity levels (ascending order)
INTEGRITY_LEVELS = ["low", "medium", "high", "critical"]
INTEGRITY_RANK = {level: i for i, level in enumerate(INTEGRITY_LEVELS)}

# In-memory stores
_MAX_RECORDS = 10_000
_resource_labels: dict[str, dict[str, Any]] = {}  # resource_id -> label record
_agent_clearances: dict[str, dict[str, Any]] = {}  # agent_id -> clearance record
_taint_records: list[dict[str, Any]] = []  # flow/taint history
_flow_violations: list[dict[str, Any]] = []  # blocked flows


def assign_resource_label(
    *,
    resource_id: str,
    confidentiality: str = "public",
    integrity: str = "medium",
    owner_agent_id: str | None = None,
    metadata: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Assign a confidentiality/integrity label to a resource."""
    if confidentiality not in CONFIDENTIALITY_RANK:
        raise ValueError(f"invalid confidentiality: {confidentiality}, valid: {CONFIDENTIALITY_LEVELS}")
    if integrity not in INTEGRITY_RANK:
        raise ValueError(f"invalid integrity: {integrity}, valid: {INTEGRITY_LEVELS}")

    now = time.time()
    record: dict[str, Any] = {
        "resource_id": resource_id,
        "confidentiality": confidentiality,
        "integrity": integrity,
        "owner_agent_id": owner_agent_id,
        "metadata": metadata or {},
        "assigned_at": now,
        "updated_at": now,
    }
    _resource_labels[resource_id] = record
    _log.info("label assigned: resource=%s conf=%s int=%s", resource_id, confidentiality, integrity)
    return record


def get_resource_label(resource_id: str) -> dict[str, Any]:
    """Get the label for a resource."""
    label = _resource_labels.get(resource_id)
    if label is None:
        raise KeyError(f"resource label not found: {resource_id}")
    return label


def assign_agent_clearance(
    *,
    agent_id: str,
    max_confidentiality: str = "confidential",
    min_integrity: str = "medium",
) -> dict[str, Any]:
    """Assign clearance levels to an agent."""
    if max_confidentiality not in CONFIDENTIALITY_RANK:
        raise ValueError(f"invalid confidentiality: {max_confidentiality}")
    if min_integrity not in INTEGRITY_RANK:
        raise ValueError(f"invalid integrity: {min_integrity}")

    now = time.time()
    record: dict[str, Any] = {
        "agent_id": agent_id,
        "max_confidentiality": max_confidentiality,
        "min_integrity": min_integrity,
        "assigned_at": now,
    }
    _agent_clearances[agent_id] = record
    _log.info("clearance assigned: agent=%s max_conf=%s min_int=%s", agent_id, max_confidentiality, min_integrity)
    return record


def get_agent_clearance(agent_id: str) -> dict[str, Any]:
    """Get the clearance for an agent. Returns default if not assigned."""
    clearance = _agent_clearances.get(agent_id)
    if clearance is None:
        return {
            "agent_id": agent_id,
            "max_confidentiality": "public",
            "min_integrity": "low",
            "assigned_at": None,
            "default": True,
        }
    return clearance


def check_read_access(
    *,
    agent_id: str,
    resource_id: str,
) -> dict[str, Any]:
    """Check if an agent can read a resource (no read up).

    Agent can read if:
    - resource confidentiality <= agent max_confidentiality
    - resource integrity >= agent min_integrity
    """
    clearance = get_agent_clearance(agent_id)
    label = _resource_labels.get(resource_id)
    if label is None:
        return {"allowed": True, "reason": "unlabeled resource", "resource_id": resource_id}

    agent_conf_rank = CONFIDENTIALITY_RANK.get(clearance["max_confidentiality"], 0)
    resource_conf_rank = CONFIDENTIALITY_RANK.get(label["confidentiality"], 0)
    agent_int_rank = INTEGRITY_RANK.get(clearance["min_integrity"], 0)
    resource_int_rank = INTEGRITY_RANK.get(label["integrity"], 0)

    conf_ok = resource_conf_rank <= agent_conf_rank
    int_ok = resource_int_rank >= agent_int_rank

    allowed = conf_ok and int_ok
    reasons: list[str] = []
    if not conf_ok:
        reasons.append(f"confidentiality too high: resource={label['confidentiality']} > agent={clearance['max_confidentiality']}")
    if not int_ok:
        reasons.append(f"integrity too low: resource={label['integrity']} < agent={clearance['min_integrity']}")

    if not allowed:
        _flow_violations.append({
            "violation_id": f"fv-{uuid.uuid4().hex[:12]}",
            "type": "read_denied",
            "agent_id": agent_id,
            "resource_id": resource_id,
            "reasons": reasons,
            "timestamp": time.time(),
        })
        if len(_flow_violations) > _MAX_RECORDS:
            _flow_violations[:] = _flow_violations[-_MAX_RECORDS:]

    return {
        "allowed": allowed,
        "agent_id": agent_id,
        "resource_id": resource_id,
        "resource_confidentiality": label["confidentiality"],
        "resource_integrity": label["integrity"],
        "agent_max_confidentiality": clearance["max_confidentiality"],
        "agent_min_integrity": clearance["min_integrity"],
        "reasons": reasons,
    }


def check_write_access(
    *,
    agent_id: str,
    resource_id: str,
) -> dict[str, Any]:
    """Check if an agent can write to a resource (no write down).

    Agent can write if:
    - resource confidentiality >= agent max_confidentiality (no write down)
    - resource integrity <= agent min_integrity
    """
    clearance = get_agent_clearance(agent_id)
    label = _resource_labels.get(resource_id)
    if label is None:
        return {"allowed": True, "reason": "unlabeled resource", "resource_id": resource_id}

    agent_conf_rank = CONFIDENTIALITY_RANK.get(clearance["max_confidentiality"], 0)
    resource_conf_rank = CONFIDENTIALITY_RANK.get(label["confidentiality"], 0)
    agent_int_rank = INTEGRITY_RANK.get(clearance["min_integrity"], 0)
    resource_int_rank = INTEGRITY_RANK.get(label["integrity"], 0)

    # No write down: can only write to same or higher confidentiality
    conf_ok = resource_conf_rank >= agent_conf_rank
    # Integrity: can write to same or lower integrity
    int_ok = resource_int_rank <= agent_int_rank

    allowed = conf_ok and int_ok
    reasons: list[str] = []
    if not conf_ok:
        reasons.append(f"write down denied: resource={label['confidentiality']} < agent={clearance['max_confidentiality']}")
    if not int_ok:
        reasons.append(f"integrity write up denied: resource={label['integrity']} > agent={clearance['min_integrity']}")

    if not allowed:
        _flow_violations.append({
            "violation_id": f"fv-{uuid.uuid4().hex[:12]}",
            "type": "write_denied",
            "agent_id": agent_id,
            "resource_id": resource_id,
            "reasons": reasons,
            "timestamp": time.time(),
        })
        if len(_flow_violations) > _MAX_RECORDS:
            _flow_violations[:] = _flow_violations[-_MAX_RECORDS:]

    return {
        "allowed": allowed,
        "agent_id": agent_id,
        "resource_id": resource_id,
        "resource_confidentiality": label["confidentiality"],
        "resource_integrity": label["integrity"],
        "agent_max_confidentiality": clearance["max_confidentiality"],
        "agent_min_integrity": clearance["min_integrity"],
        "reasons": reasons,
    }


def record_taint(
    *,
    source_resource_id: str,
    target_resource_id: str,
    agent_id: str,
    operation: str = "copy",
) -> dict[str, Any]:
    """Record information flow (taint propagation) between resources.

    When data flows from source to target, the target inherits the
    maximum confidentiality and maximum integrity from both.
    """
    source_label = _resource_labels.get(source_resource_id)
    target_label = _resource_labels.get(target_resource_id)

    if source_label is None:
        raise KeyError(f"source resource label not found: {source_resource_id}")

    now = time.time()

    # Propagate: target gets max(source, target) for confidentiality
    if target_label:
        src_conf = CONFIDENTIALITY_RANK.get(source_label["confidentiality"], 0)
        tgt_conf = CONFIDENTIALITY_RANK.get(target_label["confidentiality"], 0)
        new_conf = CONFIDENTIALITY_LEVELS[max(src_conf, tgt_conf)]

        src_int = INTEGRITY_RANK.get(source_label["integrity"], 0)
        tgt_int = INTEGRITY_RANK.get(target_label["integrity"], 0)
        new_int = INTEGRITY_LEVELS[min(src_int, tgt_int)]  # min for integrity

        target_label["confidentiality"] = new_conf
        target_label["integrity"] = new_int
        target_label["updated_at"] = now
    else:
        # Target inherits source label
        assign_resource_label(
            resource_id=target_resource_id,
            confidentiality=source_label["confidentiality"],
            integrity=source_label["integrity"],
        )

    taint_record: dict[str, Any] = {
        "taint_id": f"taint-{uuid.uuid4().hex[:12]}",
        "source_resource_id": source_resource_id,
        "target_resource_id": target_resource_id,
        "agent_id": agent_id,
        "operation": operation,
        "source_confidentiality": source_label["confidentiality"],
        "propagated_at": now,
    }
    _taint_records.append(taint_record)
    if len(_taint_records) > _MAX_RECORDS:
        _taint_records[:] = _taint_records[-_MAX_RECORDS:]
    _log.info("taint propagated: %s -> %s by %s", source_resource_id, target_resource_id, agent_id)
    return taint_record


def get_taint_history(
    *,
    resource_id: str | None = None,
    agent_id: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Get taint propagation history."""
    results = _taint_records
    if resource_id:
        results = [t for t in results if t["source_resource_id"] == resource_id or t["target_resource_id"] == resource_id]
    if agent_id:
        results = [t for t in results if t["agent_id"] == agent_id]
    return list(reversed(results[-limit:]))


def get_flow_violations(*, limit: int = 50) -> list[dict[str, Any]]:
    """Get recent flow violations."""
    return list(reversed(_flow_violations[-limit:]))


def get_label_summary() -> dict[str, Any]:
    """Get a summary of all labeled resources and agent clearances."""
    conf_dist: dict[str, int] = {}
    for label in _resource_labels.values():
        c = label["confidentiality"]
        conf_dist[c] = conf_dist.get(c, 0) + 1

    return {
        "total_labeled_resources": len(_resource_labels),
        "total_agent_clearances": len(_agent_clearances),
        "total_taint_records": len(_taint_records),
        "total_flow_violations": len(_flow_violations),
        "confidentiality_distribution": conf_dist,
    }


def reset_for_tests() -> None:
    """Clear all FIDES data for testing."""
    _resource_labels.clear()
    _agent_clearances.clear()
    _taint_records.clear()
    _flow_violations.clear()
