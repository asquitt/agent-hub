"""Consent and Authorization Registry — tracks authorization grants.

Provides:
- Record consent: principal authorizes agent for specific scopes
- Revoke consent at any time
- Query active consents per agent or principal
- Consent audit trail
- Consent expiry enforcement
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.consent_registry")

_MAX_RECORDS = 10_000
_consents: dict[str, dict[str, Any]] = {}  # consent_id -> consent record
_audit_trail: list[dict[str, Any]] = []

STATUS_ACTIVE = "active"
STATUS_REVOKED = "revoked"
STATUS_EXPIRED = "expired"


def grant_consent(
    *,
    principal_id: str,
    agent_id: str,
    scopes: list[str],
    purpose: str = "",
    ttl_seconds: int | None = None,
    conditions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record a consent grant from a principal to an agent."""
    if not scopes:
        raise ValueError("at least one scope is required")

    consent_id = f"consent-{uuid.uuid4().hex[:12]}"
    now = time.time()
    expires_at = now + ttl_seconds if ttl_seconds else None

    consent: dict[str, Any] = {
        "consent_id": consent_id,
        "principal_id": principal_id,
        "agent_id": agent_id,
        "scopes": scopes,
        "purpose": purpose,
        "conditions": conditions or {},
        "status": STATUS_ACTIVE,
        "granted_at": now,
        "expires_at": expires_at,
        "revoked_at": None,
    }

    _consents[consent_id] = consent
    _record_audit("consent.granted", consent_id, principal_id, agent_id)

    if len(_consents) > _MAX_RECORDS:
        oldest = sorted(_consents, key=lambda k: _consents[k]["granted_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _consents[k]

    return consent


def get_consent(consent_id: str) -> dict[str, Any]:
    """Get consent details."""
    consent = _consents.get(consent_id)
    if not consent:
        raise KeyError(f"consent not found: {consent_id}")
    _check_expiry(consent)
    return consent


def revoke_consent(consent_id: str, *, reason: str = "manual") -> dict[str, Any]:
    """Revoke a consent grant."""
    consent = _consents.get(consent_id)
    if not consent:
        raise KeyError(f"consent not found: {consent_id}")

    consent["status"] = STATUS_REVOKED
    consent["revoked_at"] = time.time()
    consent["revoke_reason"] = reason
    _record_audit("consent.revoked", consent_id, consent["principal_id"], consent["agent_id"])
    return consent


def list_consents(
    *,
    principal_id: str | None = None,
    agent_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List consents with optional filters."""
    results: list[dict[str, Any]] = []
    for c in _consents.values():
        _check_expiry(c)
        if principal_id and c["principal_id"] != principal_id:
            continue
        if agent_id and c["agent_id"] != agent_id:
            continue
        if status and c["status"] != status:
            continue
        results.append(c)
        if len(results) >= limit:
            break
    return results


def check_consent(
    *,
    principal_id: str,
    agent_id: str,
    scope: str,
) -> dict[str, Any]:
    """Check if a principal has granted consent for a specific scope."""
    for c in _consents.values():
        _check_expiry(c)
        if (c["principal_id"] == principal_id
                and c["agent_id"] == agent_id
                and c["status"] == STATUS_ACTIVE
                and (scope in c["scopes"] or "*" in c["scopes"])):
            return {
                "authorized": True,
                "consent_id": c["consent_id"],
                "scopes": c["scopes"],
                "granted_at": c["granted_at"],
                "expires_at": c.get("expires_at"),
            }

    return {
        "authorized": False,
        "principal_id": principal_id,
        "agent_id": agent_id,
        "scope": scope,
    }


def get_audit_trail(
    *,
    principal_id: str | None = None,
    agent_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Get consent audit trail."""
    results: list[dict[str, Any]] = []
    for entry in reversed(_audit_trail):
        if principal_id and entry["principal_id"] != principal_id:
            continue
        if agent_id and entry["agent_id"] != agent_id:
            continue
        results.append(entry)
        if len(results) >= limit:
            break
    return results


def get_consent_stats() -> dict[str, Any]:
    """Get consent registry statistics."""
    total = len(_consents)
    active = sum(1 for c in _consents.values() if c["status"] == STATUS_ACTIVE)
    revoked = sum(1 for c in _consents.values() if c["status"] == STATUS_REVOKED)
    expired = sum(1 for c in _consents.values() if c["status"] == STATUS_EXPIRED)

    return {
        "total_consents": total,
        "active_consents": active,
        "revoked_consents": revoked,
        "expired_consents": expired,
        "audit_trail_entries": len(_audit_trail),
    }


# ── Internal helpers ─────────────────────────────────────────────────

def _check_expiry(consent: dict[str, Any]) -> None:
    """Auto-expire consents past TTL."""
    if (consent["status"] == STATUS_ACTIVE
            and consent.get("expires_at")
            and consent["expires_at"] < time.time()):
        consent["status"] = STATUS_EXPIRED


def _record_audit(
    action: str,
    consent_id: str,
    principal_id: str,
    agent_id: str,
) -> None:
    """Record an audit trail entry."""
    entry: dict[str, Any] = {
        "action": action,
        "consent_id": consent_id,
        "principal_id": principal_id,
        "agent_id": agent_id,
        "timestamp": time.time(),
    }
    _audit_trail.append(entry)
    if len(_audit_trail) > _MAX_RECORDS:
        _audit_trail[:] = _audit_trail[-_MAX_RECORDS:]


def reset_for_tests() -> None:
    """Clear all consent data for testing."""
    _consents.clear()
    _audit_trail.clear()
