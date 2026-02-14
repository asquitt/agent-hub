"""Agent Discovery & Inventory — unified agent inventory with security posture.

Aggregates identity, credential, lifecycle, and federation data into a
single inventory view. Detects shadow agents (registered but no identity)
and produces per-agent security posture summaries.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from src.identity.constants import CRED_STATUS_ACTIVE, STATUS_ACTIVE

_log = logging.getLogger("agenthub.discovery")


def _safe_import_registry() -> Any:
    """Import registry store, returning None if unavailable."""
    try:
        from src.registry.store import STORE
        return STORE
    except Exception:
        return None


def _query_identity_db(sql: str, params: tuple[Any, ...] = ()) -> list[Any]:
    """Run a read query against the identity database."""
    from src.identity.storage import IDENTITY_STORAGE as _st

    _st._ensure_ready()
    with _st._lock:
        assert _st._conn is not None
        return _st._conn.execute(sql, params).fetchall()


def get_agent_inventory(
    *,
    owner: str | None = None,
    status_filter: str | None = None,
    include_credentials: bool = False,
    include_lifecycle: bool = False,
    include_posture: bool = False,
) -> dict[str, Any]:
    """Build a unified agent inventory across identity and registry stores."""
    agents: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    # 1. Identity store — agents with IAM identities
    try:
        clauses: list[str] = []
        values: list[Any] = []
        if owner:
            clauses.append("owner = ?")
            values.append(owner)
        if status_filter:
            clauses.append("status = ?")
            values.append(status_filter)
        where = " AND ".join(clauses)
        sql = "SELECT * FROM agent_identities" + (f" WHERE {where}" if where else "")
        rows = _query_identity_db(sql, tuple(values))

        for row in rows:
            agent_id = str(row["agent_id"])
            seen_ids.add(agent_id)
            entry: dict[str, Any] = {
                "agent_id": agent_id,
                "owner": str(row["owner"]),
                "status": str(row["status"]),
                "credential_type": str(row["credential_type"]),
                "has_identity": True,
                "created_at": str(row["created_at"]),
                "human_principal_id": row["human_principal_id"],
            }
            if include_credentials:
                entry["credentials"] = _get_credential_summary(agent_id)
            if include_lifecycle:
                entry["lifecycle"] = _get_lifecycle_summary(agent_id)
            if include_posture:
                entry["posture"] = _compute_agent_posture(agent_id)
            agents.append(entry)
    except Exception as exc:
        _log.warning("identity store unavailable: %s", exc)

    # 2. Registry store — agents that may lack IAM identity
    store = _safe_import_registry()
    if store is not None:
        try:
            for agent_id_key, record in store.agents.items():
                if agent_id_key in seen_ids:
                    continue
                if owner and record.owner != owner:
                    continue
                if status_filter and record.status != status_filter:
                    continue
                seen_ids.add(agent_id_key)
                agents.append({
                    "agent_id": record.agent_id,
                    "owner": record.owner,
                    "status": record.status,
                    "credential_type": None,
                    "has_identity": False,
                    "created_at": None,
                    "human_principal_id": None,
                    "shadow": True,
                })
        except Exception as exc:
            _log.warning("registry store unavailable: %s", exc)

    return {
        "total": len(agents),
        "agents": agents,
        "queried_at": time.time(),
    }


def get_agent_profile(agent_id: str) -> dict[str, Any]:
    """Build a comprehensive profile for a single agent."""
    profile: dict[str, Any] = {"agent_id": agent_id}

    # Identity
    try:
        rows = _query_identity_db(
            "SELECT * FROM agent_identities WHERE agent_id = ?", (agent_id,)
        )
        if rows:
            row = rows[0]
            profile["identity"] = {
                "owner": str(row["owner"]),
                "status": str(row["status"]),
                "credential_type": str(row["credential_type"]),
                "human_principal_id": row["human_principal_id"],
                "configuration_checksum": row["configuration_checksum"],
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
            }
        else:
            profile["identity"] = None
    except Exception:
        profile["identity"] = None

    profile["credentials"] = _get_credential_summary(agent_id)
    profile["lifecycle"] = _get_lifecycle_summary(agent_id)
    profile["posture"] = _compute_agent_posture(agent_id)

    # Registry info
    store = _safe_import_registry()
    if store is not None:
        record = store.agents.get(agent_id)
        if record:
            profile["registry"] = {
                "namespace": record.namespace,
                "slug": record.slug,
                "version_count": len(record.versions),
                "status": record.status,
            }

    profile["queried_at"] = time.time()
    return profile


def detect_shadow_agents() -> dict[str, Any]:
    """Find agents in the registry that lack IAM identities."""
    identity_agents: set[str] = set()
    try:
        rows = _query_identity_db("SELECT agent_id FROM agent_identities")
        identity_agents = {str(r["agent_id"]) for r in rows}
    except Exception as exc:
        _log.warning("cannot read identity store: %s", exc)

    shadow: list[dict[str, Any]] = []
    store = _safe_import_registry()
    registry_count = 0
    if store is not None:
        registry_count = len(store.agents)
        for agent_id_key, record in store.agents.items():
            if agent_id_key not in identity_agents:
                shadow.append({
                    "agent_id": record.agent_id,
                    "owner": record.owner,
                    "status": record.status,
                    "risk": "high" if record.status == "active" else "medium",
                    "recommendation": "Register IAM identity for this agent",
                })

    return {
        "shadow_count": len(shadow),
        "total_registry_agents": registry_count,
        "total_identity_agents": len(identity_agents),
        "shadow_agents": shadow,
        "checked_at": time.time(),
    }


def get_security_posture_summary() -> dict[str, Any]:
    """Platform-wide security posture across all agents."""
    now = time.time()
    stats: dict[str, Any] = {
        "total_agents": 0,
        "active_agents": 0,
        "agents_without_identity": 0,
        "expired_credentials": 0,
        "active_credentials": 0,
        "agents_with_human_binding": 0,
        "agents_with_checksum": 0,
        "overall_score": 0,
    }

    try:
        rows = _query_identity_db("SELECT COUNT(*) as cnt FROM agent_identities")
        stats["total_agents"] = rows[0]["cnt"] if rows else 0

        rows = _query_identity_db(
            "SELECT COUNT(*) as cnt FROM agent_identities WHERE status = ?",
            (STATUS_ACTIVE,),
        )
        stats["active_agents"] = rows[0]["cnt"] if rows else 0

        rows = _query_identity_db(
            "SELECT COUNT(*) as cnt FROM agent_credentials WHERE status = ?",
            (CRED_STATUS_ACTIVE,),
        )
        stats["active_credentials"] = rows[0]["cnt"] if rows else 0

        rows = _query_identity_db(
            "SELECT COUNT(*) as cnt FROM agent_credentials WHERE status = ? AND expires_at_epoch < ?",
            (CRED_STATUS_ACTIVE, int(now)),
        )
        stats["expired_credentials"] = rows[0]["cnt"] if rows else 0

        rows = _query_identity_db(
            "SELECT COUNT(*) as cnt FROM agent_identities WHERE human_principal_id IS NOT NULL"
        )
        stats["agents_with_human_binding"] = rows[0]["cnt"] if rows else 0

        rows = _query_identity_db(
            "SELECT COUNT(*) as cnt FROM agent_identities WHERE configuration_checksum IS NOT NULL"
        )
        stats["agents_with_checksum"] = rows[0]["cnt"] if rows else 0
    except Exception as exc:
        _log.warning("posture query failed: %s", exc)

    # Shadow agents
    store = _safe_import_registry()
    if store:
        stats["agents_without_identity"] = max(0, len(store.agents) - stats["total_agents"])

    # Score: 0-100
    total = max(stats["total_agents"], 1)
    score = 100.0
    if stats["expired_credentials"] > 0:
        score -= min(30, stats["expired_credentials"] * 10)
    if stats["agents_without_identity"] > 0:
        score -= min(30, (stats["agents_without_identity"] / total) * 30)
    if stats["agents_with_human_binding"] / total < 0.5:
        score -= 10
    if stats["agents_with_checksum"] / total < 0.5:
        score -= 10
    stats["overall_score"] = max(0, round(score))
    stats["checked_at"] = now
    return stats


def _get_credential_summary(agent_id: str) -> dict[str, Any]:
    """Get credential stats for an agent."""
    now = time.time()
    try:
        rows = _query_identity_db(
            "SELECT status, expires_at_epoch FROM agent_credentials WHERE agent_id = ?",
            (agent_id,),
        )
        total = len(rows)
        active = sum(1 for r in rows if r["status"] == CRED_STATUS_ACTIVE)
        expired = sum(
            1 for r in rows
            if r["status"] == CRED_STATUS_ACTIVE and r["expires_at_epoch"] < int(now)
        )
        return {"total": total, "active": active, "expired": expired}
    except Exception:
        return {"total": 0, "active": 0, "expired": 0}


def _get_lifecycle_summary(agent_id: str) -> dict[str, Any] | None:
    """Get lifecycle status for an agent."""
    try:
        from src.identity.lifecycle import get_lifecycle_status
        return get_lifecycle_status(agent_id)
    except (KeyError, Exception):
        return None


def _compute_agent_posture(agent_id: str) -> dict[str, Any]:
    """Compute security posture for a single agent."""
    issues: list[str] = []
    score = 100

    creds = _get_credential_summary(agent_id)
    if creds["expired"] > 0:
        issues.append(f"{creds['expired']} expired credential(s)")
        score -= 20
    if creds["active"] == 0:
        issues.append("no active credentials")
        score -= 15

    lifecycle = _get_lifecycle_summary(agent_id)
    if lifecycle and lifecycle.get("state") == "expired":
        issues.append("lifecycle state: expired")
        score -= 20

    try:
        from src.runtime.anomaly_detection import get_agent_risk_score
        risk = get_agent_risk_score(agent_id)
        if risk["risk_score"] > 50:
            issues.append(f"high anomaly risk score: {risk['risk_score']}")
            score -= 20
    except Exception:
        pass

    return {
        "score": max(0, score),
        "issues": issues,
        "risk_level": "high" if score < 40 else "medium" if score < 70 else "low",
    }
