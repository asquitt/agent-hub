"""Delegation chain visualization — tree views, scope flow, and risk analysis.

Provides structured representations of delegation chains for auditing,
debugging, and compliance visualization.
"""
from __future__ import annotations

import json as _json
import logging
from typing import Any

from src.common.time import utc_now_epoch
from src.identity.constants import MAX_DELEGATION_CHAIN_DEPTH
from src.identity.storage import IDENTITY_STORAGE

_log = logging.getLogger("agenthub.chain_viz")

# In-memory snapshot store (capped for production safety)
_MAX_SNAPSHOTS = 10_000
_snapshots: dict[str, dict[str, Any]] = {}


def _get_token_record(token_id: str) -> dict[str, Any] | None:
    """Look up a delegation token by ID from storage."""
    IDENTITY_STORAGE._ensure_ready()
    with IDENTITY_STORAGE._lock:
        conn = IDENTITY_STORAGE._conn
        assert conn is not None
        row = conn.execute(
            "SELECT * FROM delegation_tokens WHERE token_id = ?",
            (token_id,),
        ).fetchone()
        if row is None:
            return None
        record = dict(row)
        # Parse JSON scopes
        scopes_raw = record.get("delegated_scopes_json", "[]")
        if isinstance(scopes_raw, str):
            try:
                record["delegated_scopes"] = _json.loads(scopes_raw)
            except (ValueError, TypeError):
                record["delegated_scopes"] = []
        return record


_MAX_TOKENS_QUERY = 10_000


def _list_all_tokens() -> list[dict[str, Any]]:
    """List delegation tokens from storage (capped for safety)."""
    IDENTITY_STORAGE._ensure_ready()
    with IDENTITY_STORAGE._lock:
        conn = IDENTITY_STORAGE._conn
        assert conn is not None
        rows = conn.execute(
            "SELECT * FROM delegation_tokens ORDER BY issued_at_epoch DESC LIMIT ?",
            (_MAX_TOKENS_QUERY,),
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            record = dict(row)
            scopes_raw = record.get("delegated_scopes_json", "[]")
            if isinstance(scopes_raw, str):
                try:
                    record["delegated_scopes"] = _json.loads(scopes_raw)
                except (ValueError, TypeError):
                    record["delegated_scopes"] = []
            result.append(record)
        return result


def _resolve_chain(token_id: str) -> list[dict[str, Any]]:
    """Walk parent pointers to build the full chain (root-first)."""
    chain: list[dict[str, Any]] = []
    current_id: str | None = token_id
    visited: set[str] = set()
    while current_id and len(chain) < MAX_DELEGATION_CHAIN_DEPTH + 2:
        if current_id in visited:
            break  # cycle guard
        visited.add(current_id)
        record = _get_token_record(current_id)
        if record is None:
            break
        chain.append(record)
        current_id = record.get("parent_token_id")
    chain.reverse()  # root first
    return chain


def build_tree_view(token_id: str) -> dict[str, Any]:
    """Build a tree representation of a delegation chain.

    Returns a nested structure showing issuer→subject relationships,
    scope attenuation at each level, and status indicators.
    """
    chain = _resolve_chain(token_id)
    if not chain:
        raise ValueError(f"token not found: {token_id}")

    now = utc_now_epoch()
    nodes: list[dict[str, Any]] = []
    for i, tok in enumerate(chain):
        expires_epoch = tok.get("expires_at_epoch", 0)
        is_expired = isinstance(expires_epoch, (int, float)) and expires_epoch < now
        node: dict[str, Any] = {
            "depth": i,
            "token_id": tok.get("token_id", ""),
            "issuer_agent_id": tok.get("issuer_agent_id", ""),
            "subject_agent_id": tok.get("subject_agent_id", ""),
            "scopes": tok.get("delegated_scopes", []),
            "status": "expired" if is_expired else ("revoked" if tok.get("revoked") else "active"),
            "issued_at_epoch": tok.get("issued_at_epoch", 0),
            "expires_at_epoch": expires_epoch,
            "chain_depth": tok.get("chain_depth", i),
        }
        nodes.append(node)

    # Compute scope flow: how scopes narrow through the chain
    scope_flow: list[dict[str, Any]] = []
    for i, node in enumerate(nodes):
        parent_scopes = nodes[i - 1]["scopes"] if i > 0 else ["*"]
        current_scopes = node["scopes"]
        removed = sorted(set(parent_scopes) - set(current_scopes)) if "*" not in parent_scopes else []
        scope_flow.append({
            "depth": i,
            "token_id": node["token_id"],
            "inherited_scopes": parent_scopes,
            "effective_scopes": current_scopes,
            "removed_scopes": removed,
        })

    return {
        "root_token_id": chain[0].get("token_id", ""),
        "leaf_token_id": token_id,
        "chain_length": len(chain),
        "max_depth": MAX_DELEGATION_CHAIN_DEPTH,
        "nodes": nodes,
        "scope_flow": scope_flow,
    }


def analyze_chain_risk(token_id: str) -> dict[str, Any]:
    """Analyze risk factors in a delegation chain.

    Checks for: deep chains, wide scopes, expired/revoked links,
    cross-owner delegation, approaching limits.
    """
    chain = _resolve_chain(token_id)
    if not chain:
        raise ValueError(f"token not found: {token_id}")

    now = utc_now_epoch()
    risks: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []

    # Check chain depth risk
    depth = len(chain)
    if depth >= MAX_DELEGATION_CHAIN_DEPTH:
        risks.append({"code": "chain.depth_limit", "message": f"chain at max depth ({depth}/{MAX_DELEGATION_CHAIN_DEPTH})"})
    elif depth >= MAX_DELEGATION_CHAIN_DEPTH - 1:
        warnings.append({"code": "chain.depth_near_limit", "message": f"chain approaching depth limit ({depth}/{MAX_DELEGATION_CHAIN_DEPTH})"})

    # Check for broken links (revoked/expired intermediaries)
    for i, tok in enumerate(chain):
        expires_epoch = tok.get("expires_at_epoch", 0)
        is_expired = isinstance(expires_epoch, (int, float)) and expires_epoch < now
        if tok.get("revoked"):
            risks.append({"code": "chain.revoked_link", "message": f"token at depth {i} is revoked"})
        elif is_expired:
            risks.append({"code": "chain.expired_link", "message": f"token at depth {i} is expired"})

    # Check for wide scopes (wildcard delegation)
    for i, tok in enumerate(chain):
        scopes = tok.get("delegated_scopes", [])
        if "*" in scopes:
            warnings.append({"code": "scope.wildcard", "message": f"wildcard scope at depth {i}"})

    # Check for cross-owner delegation
    owners_seen: set[str] = set()
    for tok in chain:
        issuer = tok.get("issuer_agent_id", "")
        subject = tok.get("subject_agent_id", "")
        for aid in [issuer, subject]:
            if not aid:
                continue
            try:
                identity = IDENTITY_STORAGE.get_identity(aid)
                owners_seen.add(str(identity.get("owner", "")))
            except (KeyError, ValueError):
                pass
    if len(owners_seen) > 1:
        warnings.append({"code": "chain.cross_owner", "message": f"chain spans {len(owners_seen)} owners"})

    # Overall risk score (0-100)
    risk_score = min(100, len(risks) * 30 + len(warnings) * 10 + depth * 5)

    return {
        "token_id": token_id,
        "chain_length": depth,
        "risk_score": risk_score,
        "risk_level": "critical" if risk_score >= 70 else ("high" if risk_score >= 50 else ("medium" if risk_score >= 30 else "low")),
        "risks": risks,
        "warnings": warnings,
        "owners_involved": sorted(owners_seen),
    }


def list_delegation_trees(owner: str) -> list[dict[str, Any]]:
    """List all root delegation tokens (no parent) for an owner.

    Returns summary info for each tree including depth and leaf count.
    """
    all_tokens = _list_all_tokens()
    now = utc_now_epoch()

    # Build parent→children index
    children_map: dict[str, list[str]] = {}
    token_map: dict[str, dict[str, Any]] = {}
    for tok in all_tokens:
        tid = tok.get("token_id", "")
        token_map[tid] = tok
        parent = tok.get("parent_token_id")
        if parent:
            children_map.setdefault(parent, []).append(tid)

    roots: list[dict[str, Any]] = []
    for tok in all_tokens:
        if tok.get("parent_token_id"):
            continue
        # Check owner match via issuer identity
        try:
            issuer_id = IDENTITY_STORAGE.get_identity(tok.get("issuer_agent_id", ""))
            if issuer_id.get("owner") != owner:
                continue
        except (KeyError, ValueError):
            continue

        # Count descendants
        leaf_count = 0
        max_depth = 0
        active_count = 0
        queue = [(tok.get("token_id", ""), 0)]
        while queue:
            nid, d = queue.pop()
            max_depth = max(max_depth, d)
            kids = children_map.get(nid, [])
            if not kids:
                leaf_count += 1
            for kid in kids:
                queue.append((kid, d + 1))
                child_tok = token_map.get(kid)
                if child_tok:
                    exp = child_tok.get("expires_at_epoch", 0)
                    is_exp = isinstance(exp, (int, float)) and exp < now
                    if not child_tok.get("revoked") and not is_exp:
                        active_count += 1

        expires_epoch = tok.get("expires_at_epoch", 0)
        is_expired = isinstance(expires_epoch, (int, float)) and expires_epoch < now
        roots.append({
            "root_token_id": tok.get("token_id", ""),
            "issuer_agent_id": tok.get("issuer_agent_id", ""),
            "subject_agent_id": tok.get("subject_agent_id", ""),
            "scopes": tok.get("delegated_scopes", []),
            "status": "expired" if is_expired else ("revoked" if tok.get("revoked") else "active"),
            "max_depth": max_depth,
            "leaf_count": leaf_count,
            "active_descendants": active_count,
            "issued_at_epoch": tok.get("issued_at_epoch", 0),
        })

    return roots


def snapshot_chain(token_id: str, label: str = "") -> dict[str, Any]:
    """Take a point-in-time snapshot of a delegation chain for audit."""
    tree = build_tree_view(token_id)
    risk = analyze_chain_risk(token_id)
    snapshot_id = f"snap-{token_id}-{utc_now_epoch()}"

    snap: dict[str, Any] = {
        "snapshot_id": snapshot_id,
        "token_id": token_id,
        "label": label or f"snapshot of {token_id}",
        "captured_at": utc_now_epoch(),
        "tree": tree,
        "risk": risk,
    }

    # Store with cap
    if len(_snapshots) >= _MAX_SNAPSHOTS:
        oldest = min(_snapshots, key=lambda k: _snapshots[k].get("captured_at", 0))
        del _snapshots[oldest]
    _snapshots[snapshot_id] = snap
    return snap


def get_snapshot(snapshot_id: str) -> dict[str, Any]:
    """Retrieve a previously captured chain snapshot."""
    snap = _snapshots.get(snapshot_id)
    if snap is None:
        raise KeyError(f"snapshot not found: {snapshot_id}")
    return snap


def list_snapshots(token_id: str | None = None) -> list[dict[str, Any]]:
    """List chain snapshots, optionally filtered by token_id."""
    results: list[dict[str, Any]] = []
    for snap in _snapshots.values():
        if token_id and snap.get("token_id") != token_id:
            continue
        results.append({
            "snapshot_id": snap["snapshot_id"],
            "token_id": snap["token_id"],
            "label": snap["label"],
            "captured_at": snap["captured_at"],
            "chain_length": snap["tree"]["chain_length"],
            "risk_level": snap["risk"]["risk_level"],
        })
    results.sort(key=lambda s: s["captured_at"], reverse=True)
    return results


def _reset() -> None:
    """Reset state for testing."""
    _snapshots.clear()
