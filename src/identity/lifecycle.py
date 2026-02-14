"""Identity Lifecycle Orchestration — credential rotation, expiry alerts, provisioning.

Manages the full lifecycle of agent credentials: provisioning workflows,
automated rotation schedules, expiry alerts, and deprovisioning.
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from src.identity.constants import MAX_CREDENTIAL_TTL_SECONDS
from src.identity.credentials import issue_credential, revoke_credential
from src.identity.storage import get_agent_identity, register_agent_identity

_log = logging.getLogger("agenthub.lifecycle")

# Lifecycle states
STATE_PENDING = "pending"
STATE_PROVISIONED = "provisioned"
STATE_ACTIVE = "active"
STATE_ROTATION_DUE = "rotation_due"
STATE_EXPIRING = "expiring"
STATE_EXPIRED = "expired"
STATE_DEPROVISIONED = "deprovisioned"

VALID_STATES = {
    STATE_PENDING, STATE_PROVISIONED, STATE_ACTIVE,
    STATE_ROTATION_DUE, STATE_EXPIRING, STATE_EXPIRED, STATE_DEPROVISIONED,
}

# Alert thresholds (percentage of TTL remaining)
ALERT_THRESHOLD_WARNING = 0.20  # 20% TTL remaining
ALERT_THRESHOLD_CRITICAL = 0.05  # 5% TTL remaining

# In-memory lifecycle store (production would use persistent storage)
_lifecycle_records: dict[str, dict[str, Any]] = {}


def provision_agent(
    *,
    agent_id: str,
    owner: str,
    credential_type: str = "api_key",
    scopes: list[str] | None = None,
    ttl_seconds: int = 86400,
    metadata: dict[str, str] | None = None,
    auto_rotate: bool = False,
    rotation_interval_seconds: int = 86400,
) -> dict[str, Any]:
    """Full provisioning workflow: register identity + issue credential."""
    workflow_id = f"wf-{uuid.uuid4().hex[:12]}"
    now = time.time()

    steps: list[dict[str, Any]] = []

    # Step 1: Register identity
    try:
        identity = register_agent_identity(
            agent_id=agent_id,
            owner=owner,
            credential_type=credential_type,
            metadata=metadata,
        )
        steps.append({"step": "register_identity", "status": "success"})
    except ValueError:
        # Already registered — that's fine for provisioning
        identity = get_agent_identity(agent_id)
        steps.append({"step": "register_identity", "status": "already_exists"})

    # Step 2: Issue credential
    cred = issue_credential(
        agent_id=agent_id,
        owner=owner,
        scopes=scopes or ["read"],
        ttl_seconds=min(ttl_seconds, MAX_CREDENTIAL_TTL_SECONDS),
    )
    steps.append({"step": "issue_credential", "status": "success", "credential_id": cred["credential_id"]})

    # Step 3: Create lifecycle record
    record: dict[str, Any] = {
        "workflow_id": workflow_id,
        "agent_id": agent_id,
        "state": STATE_ACTIVE,
        "credential_id": cred["credential_id"],
        "provisioned_at": now,
        "last_rotation_at": now,
        "auto_rotate": auto_rotate,
        "rotation_interval_seconds": rotation_interval_seconds,
        "ttl_seconds": ttl_seconds,
        "next_rotation_at": now + rotation_interval_seconds if auto_rotate else None,
        "expires_at": now + ttl_seconds,
    }
    _lifecycle_records[agent_id] = record
    steps.append({"step": "lifecycle_record", "status": "created"})

    _log.info("agent provisioned: agent_id=%s workflow_id=%s", agent_id, workflow_id)

    return {
        "workflow_id": workflow_id,
        "agent_id": agent_id,
        "state": STATE_ACTIVE,
        "credential_id": cred["credential_id"],
        "steps": steps,
        "provisioned_at": now,
    }


def rotate_credential(
    *,
    agent_id: str,
    owner: str,
    new_scopes: list[str] | None = None,
    new_ttl_seconds: int = 86400,
    reason: str = "scheduled_rotation",
) -> dict[str, Any]:
    """Rotate an agent's credential: revoke old, issue new."""
    record = _lifecycle_records.get(agent_id)
    if record is None:
        raise KeyError(f"no lifecycle record for agent {agent_id}")

    now = time.time()
    old_credential_id = record.get("credential_id", "")

    # Revoke old credential
    try:
        revoke_credential(credential_id=old_credential_id, owner=owner, reason=reason)
    except (KeyError, PermissionError):
        pass  # Already revoked or not found — continue with rotation

    # Issue new credential
    effective_ttl = min(new_ttl_seconds, MAX_CREDENTIAL_TTL_SECONDS)
    new_cred = issue_credential(
        agent_id=agent_id,
        owner=owner,
        scopes=new_scopes or ["read"],
        ttl_seconds=effective_ttl,
    )

    # Update lifecycle record
    record["credential_id"] = new_cred["credential_id"]
    record["last_rotation_at"] = now
    record["state"] = STATE_ACTIVE
    record["expires_at"] = now + effective_ttl
    if record.get("auto_rotate"):
        record["next_rotation_at"] = now + record.get("rotation_interval_seconds", 86400)

    _log.info(
        "credential rotated: agent_id=%s old=%s new=%s reason=%s",
        agent_id, old_credential_id, new_cred["credential_id"], reason,
    )

    return {
        "agent_id": agent_id,
        "old_credential_id": old_credential_id,
        "new_credential_id": new_cred["credential_id"],
        "rotated_at": now,
        "reason": reason,
        "next_rotation_at": record.get("next_rotation_at"),
    }


def check_expiry_alerts(agent_id: str | None = None) -> list[dict[str, Any]]:
    """Check for credential expiry alerts across all or a specific agent."""
    now = time.time()
    alerts: list[dict[str, Any]] = []

    records = (
        {agent_id: _lifecycle_records[agent_id]}
        if agent_id and agent_id in _lifecycle_records
        else _lifecycle_records
    )

    for aid, record in records.items():
        if record["state"] in {STATE_DEPROVISIONED, STATE_EXPIRED}:
            continue

        expires_at = record.get("expires_at", 0)
        ttl = record.get("ttl_seconds", 86400)
        remaining = expires_at - now
        remaining_pct = remaining / ttl if ttl > 0 else 0

        if remaining <= 0:
            record["state"] = STATE_EXPIRED
            alerts.append({
                "agent_id": aid,
                "severity": "critical",
                "type": "expired",
                "message": f"credential expired {abs(remaining):.0f}s ago",
                "credential_id": record.get("credential_id", ""),
            })
        elif remaining_pct <= ALERT_THRESHOLD_CRITICAL:
            record["state"] = STATE_EXPIRING
            alerts.append({
                "agent_id": aid,
                "severity": "critical",
                "type": "expiring_soon",
                "message": f"credential expires in {remaining:.0f}s ({remaining_pct:.1%} TTL remaining)",
                "credential_id": record.get("credential_id", ""),
            })
        elif remaining_pct <= ALERT_THRESHOLD_WARNING:
            record["state"] = STATE_EXPIRING
            alerts.append({
                "agent_id": aid,
                "severity": "warning",
                "type": "expiring_warning",
                "message": f"credential expires in {remaining:.0f}s ({remaining_pct:.1%} TTL remaining)",
                "credential_id": record.get("credential_id", ""),
            })

    return alerts


def check_rotation_due(agent_id: str | None = None) -> list[dict[str, Any]]:
    """Check for credentials due for rotation."""
    now = time.time()
    due: list[dict[str, Any]] = []

    records = (
        {agent_id: _lifecycle_records[agent_id]}
        if agent_id and agent_id in _lifecycle_records
        else _lifecycle_records
    )

    for aid, record in records.items():
        if not record.get("auto_rotate"):
            continue
        if record["state"] in {STATE_DEPROVISIONED, STATE_EXPIRED}:
            continue

        next_rotation = record.get("next_rotation_at")
        if next_rotation and now >= next_rotation:
            record["state"] = STATE_ROTATION_DUE
            due.append({
                "agent_id": aid,
                "credential_id": record.get("credential_id", ""),
                "next_rotation_at": next_rotation,
                "overdue_seconds": now - next_rotation,
            })

    return due


def deprovision_agent(*, agent_id: str, owner: str, reason: str = "manual") -> dict[str, Any]:
    """Deprovision an agent: revoke credential and mark deprovisioned."""
    record = _lifecycle_records.get(agent_id)
    if record is None:
        raise KeyError(f"no lifecycle record for agent {agent_id}")

    # Revoke credential
    cred_id = record.get("credential_id", "")
    try:
        revoke_credential(credential_id=cred_id, owner=owner, reason=f"deprovisioned: {reason}")
    except (KeyError, PermissionError):
        pass

    record["state"] = STATE_DEPROVISIONED
    record["deprovisioned_at"] = time.time()

    _log.info("agent deprovisioned: agent_id=%s reason=%s", agent_id, reason)

    return {
        "agent_id": agent_id,
        "state": STATE_DEPROVISIONED,
        "credential_id": cred_id,
        "reason": reason,
        "deprovisioned_at": record["deprovisioned_at"],
    }


def get_lifecycle_status(agent_id: str) -> dict[str, Any]:
    """Get the current lifecycle status for an agent."""
    record = _lifecycle_records.get(agent_id)
    if record is None:
        raise KeyError(f"no lifecycle record for agent {agent_id}")

    now = time.time()
    expires_at = record.get("expires_at", 0)
    remaining = max(0, expires_at - now)

    return {
        "agent_id": agent_id,
        "state": record["state"],
        "credential_id": record.get("credential_id", ""),
        "provisioned_at": record.get("provisioned_at"),
        "last_rotation_at": record.get("last_rotation_at"),
        "auto_rotate": record.get("auto_rotate", False),
        "next_rotation_at": record.get("next_rotation_at"),
        "expires_at": expires_at,
        "ttl_remaining_seconds": remaining,
    }


def reset_for_tests() -> None:
    """Clear all lifecycle records for testing."""
    _lifecycle_records.clear()
