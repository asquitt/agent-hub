from __future__ import annotations

import uuid
from typing import Any

from src.common.time import iso_from_epoch, utc_now_epoch
from src.identity.constants import CRED_STATUS_REVOKED, STATUS_REVOKED
from src.identity.storage import IDENTITY_STORAGE


def revoke_agent(
    *,
    agent_id: str,
    owner: str,
    reason: str = "manual_revocation",
) -> dict[str, Any]:
    """Kill switch: revoke an agent identity plus all credentials and delegation tokens."""
    identity = IDENTITY_STORAGE.get_identity(agent_id)
    if identity["owner"] != owner:
        raise PermissionError("owner mismatch")

    # 1. Revoke all credentials
    cred_count = IDENTITY_STORAGE.revoke_all_credentials(agent_id, reason)

    # 2. Revoke all delegation tokens issued by this agent
    token_count = _revoke_agent_delegation_tokens(agent_id)

    # 3. Revoke associated leases
    lease_count = 0
    try:
        from src.lease.service import revoke_leases_for_agent

        lease_count = revoke_leases_for_agent(agent_id, reason)
    except (ImportError, RuntimeError):
        pass  # Lease module not available

    # 4. Suspend the identity itself
    IDENTITY_STORAGE.update_identity_status(agent_id, STATUS_REVOKED)

    cascade_count = cred_count + token_count + lease_count
    event_id = _record_event(
        revoked_type="agent_identity",
        revoked_id=agent_id,
        agent_id=agent_id,
        reason=reason,
        actor=owner,
        cascade_count=cascade_count,
    )

    return {
        "event_id": event_id,
        "agent_id": agent_id,
        "revoked_credentials": cred_count,
        "revoked_tokens": token_count,
        "revoked_leases": lease_count,
        "reason": reason,
    }


def bulk_revoke(
    *,
    agent_ids: list[str],
    owner: str,
    reason: str = "security_incident",
) -> dict[str, Any]:
    """Bulk kill switch for security incidents."""
    results: list[dict[str, Any]] = []
    for agent_id in agent_ids:
        try:
            result = revoke_agent(agent_id=agent_id, owner=owner, reason=reason)
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
    agent_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List revocation events, optionally filtered by agent."""
    IDENTITY_STORAGE._ensure_ready()
    conn = IDENTITY_STORAGE._conn
    assert conn is not None

    if agent_id:
        rows = conn.execute(
            "SELECT * FROM revocation_events WHERE agent_id = ? ORDER BY created_at DESC LIMIT ?",
            (agent_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM revocation_events ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


# --- Internal helpers ---


def _revoke_agent_delegation_tokens(agent_id: str) -> int:
    """Revoke all delegation tokens where agent is the issuer."""
    IDENTITY_STORAGE._ensure_ready()
    conn = IDENTITY_STORAGE._conn
    assert conn is not None
    now = iso_from_epoch(utc_now_epoch())

    # Revoke tokens issued by this agent
    result = conn.execute(
        """
        UPDATE delegation_tokens
        SET revoked = 1, revoked_at = ?
        WHERE issuer_agent_id = ? AND revoked = 0
        """,
        (now, agent_id),
    )
    direct_count = result.rowcount

    # Also revoke tokens where this agent is the subject (they can no longer act)
    result2 = conn.execute(
        """
        UPDATE delegation_tokens
        SET revoked = 1, revoked_at = ?
        WHERE subject_agent_id = ? AND revoked = 0
        """,
        (now, agent_id),
    )
    conn.commit()
    return direct_count + result2.rowcount


def _record_event(
    *,
    revoked_type: str,
    revoked_id: str,
    agent_id: str,
    reason: str,
    actor: str,
    cascade_count: int,
) -> str:
    """Record a revocation event for audit."""
    IDENTITY_STORAGE._ensure_ready()
    conn = IDENTITY_STORAGE._conn
    assert conn is not None

    event_id = f"rev-{uuid.uuid4().hex[:16]}"
    with conn:
        conn.execute(
            """
            INSERT INTO revocation_events(
                event_id, revoked_type, revoked_id, agent_id, reason, actor, cascade_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, revoked_type, revoked_id, agent_id, reason, actor, cascade_count),
        )
    return event_id
