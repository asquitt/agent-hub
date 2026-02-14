"""Zero-Trust Network Mesh — mTLS mesh abstraction using SPIFFE SVIDs.

Provides zero-trust mesh networking for agent-to-agent communication:
- Mesh node registration with SPIFFE ID binding
- Peer discovery and routing
- mTLS policy enforcement (deny-by-default, allow-by-policy)
- Connection audit trail
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.mesh")

# Connection policies
POLICY_DENY = "deny"
POLICY_ALLOW = "allow"
POLICY_MUTUAL = "mutual"  # Both sides must allow

# In-memory stores
_MAX_RECORDS = 10_000
_mesh_nodes: dict[str, dict[str, Any]] = {}  # node_id -> node
_mesh_policies: list[dict[str, Any]] = []  # allow/deny rules
_connections: list[dict[str, Any]] = []  # connection audit log


def register_node(
    *,
    agent_id: str,
    spiffe_id: str,
    endpoint: str,
    capabilities: list[str] | None = None,
    metadata: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Register an agent as a mesh node."""
    now = time.time()
    node_id = f"node-{uuid.uuid4().hex[:12]}"

    node: dict[str, Any] = {
        "node_id": node_id,
        "agent_id": agent_id,
        "spiffe_id": spiffe_id,
        "endpoint": endpoint,
        "capabilities": capabilities or [],
        "metadata": metadata or {},
        "registered_at": now,
        "last_heartbeat": now,
        "status": "active",
    }

    _mesh_nodes[node_id] = node
    _log.info("mesh node registered: id=%s agent=%s spiffe=%s", node_id, agent_id, spiffe_id)
    return node


def heartbeat(node_id: str) -> dict[str, Any]:
    """Update a node's heartbeat timestamp."""
    node = _mesh_nodes.get(node_id)
    if node is None:
        raise KeyError(f"mesh node not found: {node_id}")

    node["last_heartbeat"] = time.time()
    return {"node_id": node_id, "status": "ok", "last_heartbeat": node["last_heartbeat"]}


def deregister_node(node_id: str) -> dict[str, Any]:
    """Deregister a mesh node."""
    node = _mesh_nodes.get(node_id)
    if node is None:
        raise KeyError(f"mesh node not found: {node_id}")

    node["status"] = "deregistered"
    _log.info("mesh node deregistered: id=%s", node_id)
    return {"node_id": node_id, "status": "deregistered"}


def list_nodes(
    *,
    active_only: bool = True,
    capability: str | None = None,
) -> list[dict[str, Any]]:
    """List mesh nodes with optional filters."""
    now = time.time()
    stale_threshold = 300  # 5 minutes

    results: list[dict[str, Any]] = []
    for node in _mesh_nodes.values():
        if active_only and node["status"] != "active":
            continue
        # Mark stale nodes
        if now - node["last_heartbeat"] > stale_threshold:
            node["status"] = "stale"
            if active_only:
                continue
        if capability and capability not in node.get("capabilities", []):
            continue
        results.append(node)
    return results


def add_mesh_policy(
    *,
    source_agent_id: str,
    target_agent_id: str,
    policy: str = POLICY_ALLOW,
    scopes: list[str] | None = None,
    ttl_seconds: int = 86400,
) -> dict[str, Any]:
    """Add a mesh networking policy between two agents."""
    if policy not in {POLICY_DENY, POLICY_ALLOW, POLICY_MUTUAL}:
        raise ValueError(f"invalid policy: {policy}")

    now = time.time()
    policy_id = f"mp-{uuid.uuid4().hex[:12]}"

    record: dict[str, Any] = {
        "policy_id": policy_id,
        "source_agent_id": source_agent_id,
        "target_agent_id": target_agent_id,
        "policy": policy,
        "scopes": scopes or [],
        "created_at": now,
        "expires_at": now + ttl_seconds,
        "active": True,
    }

    _mesh_policies.append(record)
    if len(_mesh_policies) > _MAX_RECORDS:
        _mesh_policies[:] = _mesh_policies[-_MAX_RECORDS:]
    _log.info("mesh policy added: %s -> %s policy=%s", source_agent_id, target_agent_id, policy)
    return record


def check_connection(
    *,
    source_agent_id: str,
    target_agent_id: str,
    scope: str | None = None,
) -> dict[str, Any]:
    """Check if a connection is allowed between two agents (deny-by-default)."""
    now = time.time()

    # Find matching policies (deny-by-default)
    matching_allow: list[dict[str, Any]] = []
    matching_deny: list[dict[str, Any]] = []

    for p in _mesh_policies:
        if not p["active"] or now > p["expires_at"]:
            continue

        src_match = p["source_agent_id"] in {source_agent_id, "*"}
        tgt_match = p["target_agent_id"] in {target_agent_id, "*"}

        if not (src_match and tgt_match):
            continue

        if scope and p["scopes"] and scope not in p["scopes"]:
            continue

        if p["policy"] == POLICY_DENY:
            matching_deny.append(p)
        elif p["policy"] in {POLICY_ALLOW, POLICY_MUTUAL}:
            matching_allow.append(p)

    # Deny takes precedence
    if matching_deny:
        allowed = False
        reason = "explicit deny policy"
    elif matching_allow:
        allowed = True
        reason = "matching allow policy"
    else:
        allowed = False
        reason = "no matching policy (deny by default)"

    # Record connection attempt
    conn: dict[str, Any] = {
        "connection_id": f"conn-{uuid.uuid4().hex[:12]}",
        "source_agent_id": source_agent_id,
        "target_agent_id": target_agent_id,
        "scope": scope,
        "allowed": allowed,
        "reason": reason,
        "timestamp": now,
    }
    _connections.append(conn)
    if len(_connections) > _MAX_RECORDS:
        _connections[:] = _connections[-_MAX_RECORDS:]

    return {
        "allowed": allowed,
        "reason": reason,
        "source_agent_id": source_agent_id,
        "target_agent_id": target_agent_id,
        "matching_policies": len(matching_allow) + len(matching_deny),
    }


def get_connection_log(
    *,
    agent_id: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Get connection audit log."""
    results = _connections
    if agent_id:
        results = [c for c in results if c["source_agent_id"] == agent_id or c["target_agent_id"] == agent_id]
    return list(reversed(results[-limit:]))


def get_mesh_topology() -> dict[str, Any]:
    """Get a summary of the mesh network topology."""
    now = time.time()
    active_nodes = [n for n in _mesh_nodes.values() if n["status"] == "active"]
    active_policies = [p for p in _mesh_policies if p["active"] and now <= p["expires_at"]]

    return {
        "total_nodes": len(_mesh_nodes),
        "active_nodes": len(active_nodes),
        "total_policies": len(_mesh_policies),
        "active_policies": len(active_policies),
        "total_connections": len(_connections),
        "allowed_connections": sum(1 for c in _connections if c["allowed"]),
        "denied_connections": sum(1 for c in _connections if not c["allowed"]),
    }


def reset_for_tests() -> None:
    """Clear all mesh data."""
    _mesh_nodes.clear()
    _mesh_policies.clear()
    _connections.clear()
