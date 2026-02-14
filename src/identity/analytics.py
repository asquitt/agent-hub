"""Identity Analytics — credential usage statistics, delegation patterns, access trends.

Provides aggregate analytics across the identity system:
- Credential utilization (active vs expired vs revoked)
- Delegation chain depth distributions
- Access pattern analysis
- Compliance posture scoring
"""
from __future__ import annotations

import json
import sqlite3
import time
from typing import Any

from src.identity.storage import IDENTITY_STORAGE


def _get_conn() -> sqlite3.Connection | None:
    """Get the identity storage connection, returning None if unavailable."""
    try:
        IDENTITY_STORAGE._ensure_ready()
    except Exception:
        pass
    return IDENTITY_STORAGE._conn


def _count(query: str, params: tuple[object, ...] = ()) -> int:
    """Execute a COUNT query safely."""
    conn = _get_conn()
    if conn is None:
        return 0
    try:
        row = conn.execute(query, params).fetchone()
        return int(row[0]) if row else 0
    except sqlite3.OperationalError:
        return 0


def _fetchall(query: str, params: tuple[object, ...] = ()) -> list[Any]:
    """Execute a query safely, returning rows or empty list."""
    conn = _get_conn()
    if conn is None:
        return []
    try:
        return conn.execute(query, params).fetchall()
    except sqlite3.OperationalError:
        return []


def get_credential_statistics() -> dict[str, Any]:
    """Aggregate statistics on credential lifecycle."""
    now = time.time()

    total = _count("SELECT COUNT(*) FROM credentials")
    active = _count("SELECT COUNT(*) FROM credentials WHERE status = 'active' AND expires_at > ?", (now,))
    revoked = _count("SELECT COUNT(*) FROM credentials WHERE status = 'revoked'")
    expired = _count("SELECT COUNT(*) FROM credentials WHERE status = 'active' AND expires_at <= ?", (now,))

    rows = _fetchall("SELECT scopes_json FROM credentials WHERE status = 'active' AND expires_at > ?", (now,))
    scope_counts: dict[str, int] = {}
    for (scopes_json,) in rows:
        try:
            scopes: list[str] = json.loads(scopes_json) if scopes_json else []
        except (json.JSONDecodeError, TypeError):
            scopes = []
        for s in scopes:
            scope_counts[s] = scope_counts.get(s, 0) + 1

    return {
        "total_credentials": total,
        "active": active,
        "revoked": revoked,
        "expired": expired,
        "utilization_rate": round(active / total, 3) if total > 0 else 0,
        "scope_distribution": scope_counts,
        "computed_at": now,
    }


def get_identity_statistics() -> dict[str, Any]:
    """Aggregate statistics on agent identities."""
    total = _count("SELECT COUNT(*) FROM agent_identities")
    active = _count("SELECT COUNT(*) FROM agent_identities WHERE status = 'active'")
    suspended = _count("SELECT COUNT(*) FROM agent_identities WHERE status = 'suspended'")

    rows = _fetchall("SELECT credential_type, COUNT(*) FROM agent_identities GROUP BY credential_type")
    type_dist: dict[str, int] = {row[0]: row[1] for row in rows}

    return {
        "total_identities": total,
        "active": active,
        "suspended": suspended,
        "type_distribution": type_dist,
        "computed_at": time.time(),
    }


def get_delegation_statistics() -> dict[str, Any]:
    """Statistics on delegation token usage and chain depths."""
    total = _count("SELECT COUNT(*) FROM delegation_tokens")
    active = _count("SELECT COUNT(*) FROM delegation_tokens WHERE status = 'active'")
    revoked = _count("SELECT COUNT(*) FROM delegation_tokens WHERE status = 'revoked'")

    rows = _fetchall("SELECT chain_depth, COUNT(*) FROM delegation_tokens GROUP BY chain_depth")
    depth_dist: dict[str, int] = {str(row[0]): row[1] for row in rows}

    return {
        "total_tokens": total,
        "active": active,
        "revoked": revoked,
        "chain_depth_distribution": depth_dist,
        "computed_at": time.time(),
    }


def get_identity_health_score() -> dict[str, Any]:
    """Compute an overall identity system health score (0-100)."""
    cred_stats = get_credential_statistics()
    id_stats = get_identity_statistics()

    score = 100
    issues: list[str] = []

    total_creds = cred_stats["total_credentials"]
    if total_creds > 0:
        expired_ratio = cred_stats["expired"] / total_creds
        if expired_ratio > 0.3:
            score -= int(expired_ratio * 30)
            issues.append(f"{cred_stats['expired']} expired credentials ({expired_ratio:.0%})")

    util = cred_stats.get("utilization_rate", 0)
    if total_creds > 5 and isinstance(util, (int, float)) and util < 0.5:
        score -= 15
        issues.append(f"low credential utilization ({util:.0%})")

    total_ids = id_stats["total_identities"]
    if total_ids > 0:
        suspended_ratio = id_stats["suspended"] / total_ids
        if suspended_ratio > 0.1:
            score -= 10
            issues.append(f"{id_stats['suspended']} suspended identities ({suspended_ratio:.0%})")

    score = max(0, score)

    if score >= 80:
        level = "healthy"
    elif score >= 60:
        level = "warning"
    elif score >= 40:
        level = "degraded"
    else:
        level = "critical"

    return {
        "health_score": score,
        "health_level": level,
        "issues": issues,
        "credential_stats": cred_stats,
        "identity_stats": id_stats,
        "computed_at": time.time(),
    }
