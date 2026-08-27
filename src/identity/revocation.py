from __future__ import annotations

import uuid
from typing import Any

from src.common.time import iso_from_epoch, utc_now_epoch
from src.identity.constants import STATUS_REVOKED
from src.identity.storage import (
    IDENTITY_STORAGE,
    ResourceAuthContext,
    require_resource_actor,
)


def revoke_agent(
    *,
    agent_id: str,
    actor: ResourceAuthContext,
    reason: str = "manual_revocation",
) -> dict[str, Any]:
    """Kill switch: revoke an agent identity plus all credentials and delegation tokens."""
    context = require_resource_actor(actor)
    IDENTITY_STORAGE.get_identity_for_actor(agent_id, context)

    cred_count = 0
    token_count = 0
    lease_count = 0
    capability_count = 0
    vc_count = 0
    try:
        # 1. Revoke all credentials
        cred_count = IDENTITY_STORAGE.revoke_all_credentials(agent_id, reason)

        # 2. Revoke all delegation tokens issued by this agent
        token_count = _revoke_agent_delegation_tokens(agent_id, context)

        # 3. Revoke associated leases
        try:
            from src.lease.service import revoke_leases_for_agent

            lease_count = revoke_leases_for_agent(agent_id, reason)
        except (ImportError, RuntimeError):
            pass  # Lease module not available

        # 4. Revoke durable capability and credential authority artifacts.
        capability_count, vc_count = (
            IDENTITY_STORAGE.revoke_authority_artifacts_for_agent(
                agent_id=agent_id,
                actor=context,
                reason=reason,
            )
        )
    finally:
        # 5. Always revoke the identity — even if an upstream cascade fails.
        IDENTITY_STORAGE.update_identity_status_for_actor(
            agent_id, STATUS_REVOKED, context
        )

    cascade_count = cred_count + token_count + lease_count + capability_count + vc_count
    event_id = _record_event(
        revoked_type="agent_identity",
        revoked_id=agent_id,
        agent_id=agent_id,
        reason=reason,
        actor=context,
        cascade_count=cascade_count,
    )

    return {
        "event_id": event_id,
        "agent_id": agent_id,
        "revoked_credentials": cred_count,
        "revoked_tokens": token_count,
        "revoked_capability_tokens": capability_count,
        "revoked_verifiable_credentials": vc_count,
        "revoked_leases": lease_count,
        "reason": reason,
    }


def bulk_revoke(
    *,
    agent_ids: list[str],
    actor: ResourceAuthContext,
    reason: str = "security_incident",
) -> dict[str, Any]:
    """Bulk kill switch for security incidents."""
    results: list[dict[str, Any]] = []
    for agent_id in agent_ids:
        try:
            result = revoke_agent(agent_id=agent_id, actor=actor, reason=reason)
            results.append(result)
        except (KeyError, PermissionError) as exc:
            results.append({"agent_id": agent_id, "error": str(exc)})

    return {
        "total_requested": len(agent_ids),
        "total_revoked": sum(1 for r in results if "event_id" in r),
        "results": results,
    }


def list_revocation_events(
    *,
    actor: ResourceAuthContext,
    agent_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List revocation events, optionally filtered by agent."""
    context = require_resource_actor(actor)
    if agent_id is not None:
        IDENTITY_STORAGE.get_identity_for_actor(agent_id, context)
    IDENTITY_STORAGE._ensure_ready()
    with IDENTITY_STORAGE._lock:
        conn = IDENTITY_STORAGE._conn
        assert conn is not None

        clauses = ["owner = ?", "tenant_id = ?"]
        params: list[object] = [context.owner, context.tenant_id]
        if context.agent_id is not None:
            clauses.append("agent_id = ?")
            params.append(context.agent_id)
        if agent_id is not None:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        params.append(max(1, min(int(limit), 1000)))
        rows = conn.execute(
            f"SELECT * FROM revocation_events WHERE {' AND '.join(clauses)} "  # noqa: S608
            "ORDER BY created_at DESC LIMIT ?",
            params,
        ).fetchall()

        return [dict(row) for row in rows]


# --- Internal helpers ---


def _revoke_agent_delegation_tokens(
    agent_id: str,
    actor: ResourceAuthContext,
) -> int:
    """Revoke all delegation tokens where agent is the issuer."""
    IDENTITY_STORAGE._ensure_ready()
    with IDENTITY_STORAGE._lock:
        conn = IDENTITY_STORAGE._conn
        assert conn is not None
        now = iso_from_epoch(utc_now_epoch())

        with conn:
            # Revoke tokens issued by this agent
            result = conn.execute(
                """
                UPDATE delegation_tokens
                SET revoked = 1, revoked_at = ?
                WHERE issuer_agent_id = ? AND owner = ? AND tenant_id = ? AND revoked = 0
                """,
                (now, agent_id, actor.owner, actor.tenant_id),
            )
            direct_count = result.rowcount

            # Also revoke tokens where this agent is the subject
            result2 = conn.execute(
                """
                UPDATE delegation_tokens
                SET revoked = 1, revoked_at = ?
                WHERE subject_agent_id = ? AND owner = ? AND tenant_id = ? AND revoked = 0
                """,
                (now, agent_id, actor.owner, actor.tenant_id),
            )
        return direct_count + result2.rowcount


def _record_event(
    *,
    revoked_type: str,
    revoked_id: str,
    agent_id: str,
    reason: str,
    actor: ResourceAuthContext,
    cascade_count: int,
) -> str:
    """Record a revocation event for audit."""
    IDENTITY_STORAGE._ensure_ready()
    with IDENTITY_STORAGE._lock:
        conn = IDENTITY_STORAGE._conn
        assert conn is not None

        event_id = f"rev-{uuid.uuid4().hex[:16]}"
        with conn:
            conn.execute(
                """
                INSERT INTO revocation_events(
                    event_id, revoked_type, revoked_id, agent_id, reason, actor,
                    cascade_count, owner, tenant_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    revoked_type,
                    revoked_id,
                    agent_id,
                    reason,
                    actor.owner,
                    cascade_count,
                    actor.owner,
                    actor.tenant_id,
                ),
            )
        return event_id
