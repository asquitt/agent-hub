"""Policy Decision Graph — trace and visualize policy decision chains.

Records policy evaluation decisions with full dependency graphs,
enabling explainability and audit trails for access control decisions.
"""
from __future__ import annotations

import time
import uuid
from typing import Any

# In-memory decision store
_MAX_DECISIONS = 10_000
_decisions: list[dict[str, Any]] = []


def record_decision(
    *,
    request_id: str | None = None,
    agent_id: str,
    action: str,
    resource: str,
    decision: str,  # "allow" | "deny"
    reason: str,
    policies_evaluated: list[str] | None = None,
    conditions_checked: list[dict[str, Any]] | None = None,
    parent_decision_id: str | None = None,
    delegation_chain: list[str] | None = None,
    latency_ms: float = 0.0,
) -> dict[str, Any]:
    """Record a policy decision with full context."""
    decision_id = f"dec-{uuid.uuid4().hex[:12]}"
    now = time.time()

    record: dict[str, Any] = {
        "decision_id": decision_id,
        "request_id": request_id or f"req-{uuid.uuid4().hex[:8]}",
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "decision": decision,
        "reason": reason,
        "policies_evaluated": policies_evaluated or [],
        "conditions_checked": conditions_checked or [],
        "parent_decision_id": parent_decision_id,
        "delegation_chain": delegation_chain or [],
        "latency_ms": latency_ms,
        "recorded_at": now,
    }

    _decisions.append(record)
    if len(_decisions) > _MAX_DECISIONS:
        _decisions[:] = _decisions[-_MAX_DECISIONS:]
    return record


def get_decision(decision_id: str) -> dict[str, Any]:
    """Get a specific decision by ID."""
    for d in _decisions:
        if d["decision_id"] == decision_id:
            return d
    raise KeyError(f"decision not found: {decision_id}")


def get_decision_chain(decision_id: str) -> list[dict[str, Any]]:
    """Trace the full decision chain from a leaf decision up to root."""
    chain: list[dict[str, Any]] = []
    current_id: str | None = decision_id

    visited: set[str] = set()
    while current_id and current_id not in visited:
        visited.add(current_id)
        try:
            decision = get_decision(current_id)
            chain.append(decision)
            current_id = decision.get("parent_decision_id")
        except KeyError:
            break

    return list(reversed(chain))  # Root first


def get_decisions_for_agent(
    agent_id: str,
    *,
    limit: int = 50,
    action: str | None = None,
    decision_filter: str | None = None,
) -> list[dict[str, Any]]:
    """Get recent decisions for an agent with optional filters."""
    results = []
    for d in reversed(_decisions):
        if d["agent_id"] != agent_id:
            continue
        if action and d["action"] != action:
            continue
        if decision_filter and d["decision"] != decision_filter:
            continue
        results.append(d)
        if len(results) >= limit:
            break
    return results


def get_decision_statistics(
    *,
    start_time: float | None = None,
    end_time: float | None = None,
) -> dict[str, Any]:
    """Aggregate statistics on policy decisions."""
    now = time.time()
    filtered = _decisions

    if start_time:
        filtered = [d for d in filtered if d["recorded_at"] >= start_time]
    if end_time:
        filtered = [d for d in filtered if d["recorded_at"] <= end_time]

    total = len(filtered)
    allows = sum(1 for d in filtered if d["decision"] == "allow")
    denies = sum(1 for d in filtered if d["decision"] == "deny")

    # Per-agent breakdown
    agent_counts: dict[str, dict[str, int]] = {}
    for d in filtered:
        aid = d["agent_id"]
        if aid not in agent_counts:
            agent_counts[aid] = {"allow": 0, "deny": 0}
        agent_counts[aid][d["decision"]] = agent_counts[aid].get(d["decision"], 0) + 1

    # Latency stats
    latencies = [d.get("latency_ms", 0) for d in filtered]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    max_latency = max(latencies) if latencies else 0

    return {
        "total_decisions": total,
        "allows": allows,
        "denies": denies,
        "deny_rate": round(denies / total, 3) if total > 0 else 0,
        "agent_breakdown": agent_counts,
        "avg_latency_ms": round(avg_latency, 2),
        "max_latency_ms": round(max_latency, 2),
        "computed_at": now,
    }


def build_decision_graph(request_id: str) -> dict[str, Any]:
    """Build a graph of all decisions for a given request."""
    request_decisions = [d for d in _decisions if d.get("request_id") == request_id]

    nodes = []
    edges = []
    for d in request_decisions:
        nodes.append({
            "id": d["decision_id"],
            "agent_id": d["agent_id"],
            "action": d["action"],
            "resource": d["resource"],
            "decision": d["decision"],
        })
        if d.get("parent_decision_id"):
            edges.append({
                "from": d["parent_decision_id"],
                "to": d["decision_id"],
                "relationship": "delegated",
            })

    return {
        "request_id": request_id,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
    }


def reset_for_tests() -> None:
    """Clear all decision records for testing."""
    _decisions.clear()
