"""Blended Identity — on-behalf-of binding and verification.

Supports binding agent identities to human principals and verifying
that JWT tokens contain valid on-behalf-of claims matching stored bindings.
"""
from __future__ import annotations

from typing import Any

from src.identity.storage import IDENTITY_STORAGE


def verify_on_behalf_of(
    *,
    agent_id: str,
    claimed_principal_id: str,
) -> dict[str, Any]:
    """Verify that an agent's on-behalf-of claim matches its stored binding.

    Returns a verification result dict with match status and details.
    Raises KeyError if agent_id is not found.
    """
    identity = IDENTITY_STORAGE.get_identity(agent_id)
    stored = identity.get("human_principal_id")

    if stored is None:
        return {
            "agent_id": agent_id,
            "valid": False,
            "reason": "no_binding",
            "message": "agent has no human principal binding",
        }

    if stored != claimed_principal_id:
        return {
            "agent_id": agent_id,
            "valid": False,
            "reason": "mismatch",
            "message": "claimed principal does not match stored binding",
        }

    return {
        "agent_id": agent_id,
        "valid": True,
        "human_principal_id": stored,
    }


def get_blended_identity(agent_id: str) -> dict[str, Any]:
    """Get the full blended identity for an agent (agent + human principal).

    Returns a dict combining agent identity fields with the human principal binding.
    Raises KeyError if agent_id is not found.
    """
    identity = IDENTITY_STORAGE.get_identity(agent_id)
    return {
        "agent_id": identity["agent_id"],
        "owner": identity["owner"],
        "status": identity["status"],
        "credential_type": identity["credential_type"],
        "human_principal_id": identity.get("human_principal_id"),
        "has_human_binding": identity.get("human_principal_id") is not None,
        "configuration_checksum": identity.get("configuration_checksum"),
    }
