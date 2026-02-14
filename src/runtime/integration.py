from __future__ import annotations

from typing import Any

from src.runtime.sandbox import create_sandbox
from src.runtime.types import SandboxInstance


def create_delegated_sandbox(
    *,
    delegation_id: str,
    agent_id: str,
    owner: str,
    resource_limits: dict[str, Any] | None = None,
    profile_name: str | None = None,
) -> SandboxInstance:
    """Create a sandbox linked to a delegation contract."""
    from src.delegation import storage as delegation_storage

    record = delegation_storage.get_record(delegation_id)
    if record is None:
        raise KeyError(f"delegation not found: {delegation_id}")
    if record.get("status") not in ("queued", "running"):
        raise ValueError(f"delegation not in valid state: {record.get('status')}")

    return create_sandbox(
        agent_id=agent_id,
        owner=owner,
        profile_name=profile_name or "micro",
        resource_limits=resource_limits,
        delegation_id=delegation_id,
    )


def create_leased_sandbox(
    *,
    lease_id: str,
    agent_id: str,
    owner: str,
    resource_limits: dict[str, Any] | None = None,
    profile_name: str | None = None,
) -> SandboxInstance:
    """Create a sandbox linked to an active lease."""
    from src.lease.service import get_lease

    lease = get_lease(lease_id, owner)
    if lease["status"] != "active":
        raise ValueError(f"lease not active: {lease['status']}")

    return create_sandbox(
        agent_id=agent_id,
        owner=owner,
        profile_name=profile_name or "micro",
        resource_limits=resource_limits,
        lease_id=lease_id,
    )


def create_federated_sandbox(
    *,
    domain_id: str,
    agent_id: str,
    owner: str,
    resource_limits: dict[str, Any] | None = None,
    profile_name: str | None = None,
    agent_attestation_id: str | None = None,
) -> SandboxInstance:
    """Create a sandbox for cross-org federated execution."""
    try:
        from src.identity.federation import get_trusted_domain, verify_agent_attestation

        get_trusted_domain(domain_id)  # Raises KeyError if not trusted

        if agent_attestation_id:
            verify_agent_attestation(agent_attestation_id)
    except (ImportError, RuntimeError):
        import logging

        logging.getLogger("agenthub.runtime").warning(
            "federation module unavailable, skipping trust verification for domain=%s",
            domain_id,
        )

    return create_sandbox(
        agent_id=agent_id,
        owner=owner,
        profile_name=profile_name or "micro",
        resource_limits=resource_limits,
    )
