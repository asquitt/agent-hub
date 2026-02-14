"""Secure Multi-Party Delegation — N-of-M approval ceremonies.

Implements multi-party delegation approval requiring N out of M approvers
to authorize a delegation before it takes effect:
- Ceremony creation with quorum requirements
- Individual approver voting with HMAC signatures
- Automatic execution when quorum is reached
- Timeout and rejection handling
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.multiparty")

# Ceremony statuses
STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_EXPIRED = "expired"

# In-memory store
_ceremonies: dict[str, dict[str, Any]] = {}


def _signing_secret() -> bytes:
    secret = os.getenv("AGENTHUB_IDENTITY_SIGNING_SECRET", "")
    return secret.encode("utf-8") if secret else b"default-test-key"


def _sign_vote(ceremony_id: str, voter_id: str, decision: str) -> str:
    """Compute HMAC-SHA256 signature for a vote."""
    data = f"{ceremony_id}|{voter_id}|{decision}".encode("utf-8")
    return hmac.new(_signing_secret(), data, hashlib.sha256).hexdigest()


def create_ceremony(
    *,
    initiator_agent_id: str,
    subject_agent_id: str,
    scopes: list[str],
    approvers: list[str],
    required_approvals: int,
    ttl_seconds: int = 3600,
    metadata: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Create a multi-party delegation ceremony."""
    if required_approvals < 1:
        raise ValueError("required_approvals must be >= 1")
    if required_approvals > len(approvers):
        raise ValueError(f"required_approvals ({required_approvals}) > approver count ({len(approvers)})")
    if len(approvers) != len(set(approvers)):
        raise ValueError("duplicate approvers not allowed")
    if initiator_agent_id in approvers:
        raise ValueError("initiator cannot be an approver")

    now = time.time()
    ceremony_id = f"ceremony-{uuid.uuid4().hex[:12]}"

    ceremony: dict[str, Any] = {
        "ceremony_id": ceremony_id,
        "initiator_agent_id": initiator_agent_id,
        "subject_agent_id": subject_agent_id,
        "scopes": sorted(scopes),
        "approvers": sorted(approvers),
        "required_approvals": required_approvals,
        "votes": {},  # voter_id -> {decision, signature, timestamp}
        "status": STATUS_PENDING,
        "metadata": metadata or {},
        "created_at": now,
        "expires_at": now + ttl_seconds,
        "completed_at": None,
    }

    _ceremonies[ceremony_id] = ceremony
    _log.info(
        "ceremony created: id=%s initiator=%s subject=%s quorum=%d/%d",
        ceremony_id, initiator_agent_id, subject_agent_id, required_approvals, len(approvers),
    )
    return ceremony


def cast_vote(
    *,
    ceremony_id: str,
    voter_id: str,
    decision: str,
) -> dict[str, Any]:
    """Cast a vote on a ceremony."""
    ceremony = _ceremonies.get(ceremony_id)
    if ceremony is None:
        raise KeyError(f"ceremony not found: {ceremony_id}")

    if decision not in {"approve", "reject"}:
        raise ValueError(f"invalid decision: {decision}, must be 'approve' or 'reject'")

    now = time.time()

    # Check ceremony is still pending
    if ceremony["status"] != STATUS_PENDING:
        raise ValueError(f"ceremony is {ceremony['status']}, cannot vote")

    # Check not expired
    if now > ceremony["expires_at"]:
        ceremony["status"] = STATUS_EXPIRED
        raise ValueError("ceremony has expired")

    # Check voter is an approver
    if voter_id not in ceremony["approvers"]:
        raise ValueError(f"voter {voter_id} is not an approved approver")

    # Check not already voted
    if voter_id in ceremony["votes"]:
        raise ValueError(f"voter {voter_id} has already voted")

    # Record vote with HMAC signature
    signature = _sign_vote(ceremony_id, voter_id, decision)
    ceremony["votes"][voter_id] = {
        "decision": decision,
        "signature": signature,
        "timestamp": now,
    }

    # Check for rejection
    reject_count = sum(1 for v in ceremony["votes"].values() if v["decision"] == "reject")
    remaining_voters = len(ceremony["approvers"]) - len(ceremony["votes"])
    max_possible_approvals = len(ceremony["approvers"]) - reject_count

    if max_possible_approvals < ceremony["required_approvals"]:
        ceremony["status"] = STATUS_REJECTED
        ceremony["completed_at"] = now
        _log.info("ceremony rejected: id=%s (impossible to reach quorum)", ceremony_id)

    # Check for approval quorum
    approve_count = sum(1 for v in ceremony["votes"].values() if v["decision"] == "approve")
    if approve_count >= ceremony["required_approvals"]:
        ceremony["status"] = STATUS_APPROVED
        ceremony["completed_at"] = now
        _log.info("ceremony approved: id=%s quorum=%d/%d", ceremony_id, approve_count, ceremony["required_approvals"])

    return {
        "ceremony_id": ceremony_id,
        "voter_id": voter_id,
        "decision": decision,
        "signature": signature,
        "ceremony_status": ceremony["status"],
        "votes_cast": len(ceremony["votes"]),
        "approvals": approve_count,
        "required": ceremony["required_approvals"],
    }


def get_ceremony(ceremony_id: str) -> dict[str, Any]:
    """Get a ceremony by ID."""
    ceremony = _ceremonies.get(ceremony_id)
    if ceremony is None:
        raise KeyError(f"ceremony not found: {ceremony_id}")

    # Auto-expire
    if ceremony["status"] == STATUS_PENDING and time.time() > ceremony["expires_at"]:
        ceremony["status"] = STATUS_EXPIRED

    return ceremony


def list_ceremonies(
    *,
    initiator: str | None = None,
    status: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List ceremonies with optional filters."""
    now = time.time()
    results: list[dict[str, Any]] = []
    for c in _ceremonies.values():
        # Auto-expire
        if c["status"] == STATUS_PENDING and now > c["expires_at"]:
            c["status"] = STATUS_EXPIRED

        if initiator and c["initiator_agent_id"] != initiator:
            continue
        if status and c["status"] != status:
            continue
        results.append({
            "ceremony_id": c["ceremony_id"],
            "initiator_agent_id": c["initiator_agent_id"],
            "subject_agent_id": c["subject_agent_id"],
            "status": c["status"],
            "required_approvals": c["required_approvals"],
            "votes_cast": len(c["votes"]),
            "approver_count": len(c["approvers"]),
            "created_at": c["created_at"],
        })
        if len(results) >= limit:
            break
    return results


def verify_ceremony_signatures(ceremony_id: str) -> dict[str, Any]:
    """Verify all vote signatures in a ceremony."""
    ceremony = _ceremonies.get(ceremony_id)
    if ceremony is None:
        raise KeyError(f"ceremony not found: {ceremony_id}")

    results: list[dict[str, Any]] = []
    all_valid = True
    for voter_id, vote in ceremony["votes"].items():
        expected = _sign_vote(ceremony_id, voter_id, vote["decision"])
        valid = hmac.compare_digest(expected, vote["signature"])
        if not valid:
            all_valid = False
        results.append({
            "voter_id": voter_id,
            "decision": vote["decision"],
            "signature_valid": valid,
        })

    return {
        "ceremony_id": ceremony_id,
        "all_signatures_valid": all_valid,
        "vote_count": len(results),
        "votes": results,
    }


def reset_for_tests() -> None:
    """Clear all ceremony data."""
    _ceremonies.clear()
