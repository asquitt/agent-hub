from __future__ import annotations

import hashlib
import uuid
from typing import Any

from src.common.time import iso_from_epoch, utc_now_epoch

from . import storage as lease_storage


def _now_epoch() -> int:
    return utc_now_epoch()


def _iso_from_epoch(value: int) -> str:
    return iso_from_epoch(value)


def _expected_signature(attestation_hash: str, owner: str) -> str:
    # Deterministic signature format for local attestation simulation.
    return f"sig:{attestation_hash}:{owner}"


def _normalize_status(row: dict[str, Any], now_epoch: int | None = None) -> dict[str, Any]:
    now = _now_epoch() if now_epoch is None else now_epoch
    if row["status"] == "active" and now > int(row["expires_at_epoch"]):
        row["status"] = "expired"
    return row


def create_lease(
    requester_agent_id: str,
    capability_ref: str,
    owner: str,
    ttl_seconds: int = 3600,
) -> dict[str, Any]:
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be greater than zero")

    now = _now_epoch()
    attestation_hash = hashlib.sha256(f"{requester_agent_id}|{capability_ref}|{now}".encode("utf-8")).hexdigest()
    lease_id = str(uuid.uuid4())
    record = {
        "lease_id": lease_id,
        "requester_agent_id": requester_agent_id,
        "capability_ref": capability_ref,
        "owner": owner,
        "status": "active",
        "ttl_seconds": ttl_seconds,
        "created_at": _iso_from_epoch(now),
        "expires_at": _iso_from_epoch(now + ttl_seconds),
        "created_at_epoch": now,
        "expires_at_epoch": now + ttl_seconds,
        "attestation_hash": attestation_hash,
        "promotion": None,
    }
    leases = lease_storage.load_leases()
    leases[lease_id] = record
    lease_storage.save_leases(leases)
    return _normalize_status(record.copy(), now)


def get_lease(lease_id: str, owner: str) -> dict[str, Any]:
    leases = lease_storage.load_leases()
    if lease_id not in leases:
        raise KeyError("lease not found")
    row = leases[lease_id]
    if row["owner"] != owner:
        raise PermissionError("owner mismatch")
    previous_status = row["status"]
    _normalize_status(row)
    if row["status"] != previous_status:
        leases[lease_id] = row
        lease_storage.save_leases(leases)
    return row.copy()


def promote_lease(
    lease_id: str,
    owner: str,
    signature: str,
    attestation_hash: str,
    policy_approved: bool,
    approval_ticket: str,
    compatibility_verified: bool,
) -> dict[str, Any]:
    leases = lease_storage.load_leases()
    if lease_id not in leases:
        raise KeyError("lease not found")
    row = leases[lease_id]
    if row["owner"] != owner:
        raise PermissionError("owner mismatch")

    previous_status = row["status"]
    _normalize_status(row)
    if row["status"] != previous_status:
        leases[lease_id] = row
        lease_storage.save_leases(leases)
    if row["status"] == "expired":
        raise ValueError("lease expired")
    if row["status"] == "promoted":
        return row.copy()
    if row["status"] != "active":
        raise ValueError("lease is not active")
    if not policy_approved:
        raise PermissionError("policy approval required")
    if not approval_ticket.startswith("APR-"):
        raise PermissionError("approval ticket required")
    if not compatibility_verified:
        raise PermissionError("compatibility verification required")
    if attestation_hash != row["attestation_hash"]:
        raise PermissionError("attestation hash mismatch")
    if signature != _expected_signature(attestation_hash=attestation_hash, owner=owner):
        raise PermissionError("invalid attestation signature")

    install_id = str(uuid.uuid4())
    installs = lease_storage.load_installs()
    installs[install_id] = {
        "install_id": install_id,
        "lease_id": lease_id,
        "owner": owner,
        "requester_agent_id": row["requester_agent_id"],
        "installed_ref": f"{row['requester_agent_id']}::{row['capability_ref']}",
        "status": "active",
        "compatibility_verified": compatibility_verified,
        "approval_ticket": approval_ticket,
        "created_at": _iso_from_epoch(_now_epoch()),
        "rolled_back_at": None,
        "rollback_reason": None,
    }
    lease_storage.save_installs(installs)

    row["status"] = "promoted"
    row["promotion"] = {
        "promoted_at": _iso_from_epoch(_now_epoch()),
        "installed_ref": f"{row['requester_agent_id']}::{row['capability_ref']}",
        "attestation_hash": attestation_hash,
        "approval_ticket": approval_ticket,
        "compatibility_verified": compatibility_verified,
        "install_id": install_id,
    }
    leases[lease_id] = row
    lease_storage.save_leases(leases)
    return row.copy()


def rollback_install(install_id: str, owner: str, reason: str) -> dict[str, Any]:
    installs = lease_storage.load_installs()
    if install_id not in installs:
        raise KeyError("install not found")
    row = installs[install_id]
    if row["owner"] != owner:
        raise PermissionError("owner mismatch")
    if row["status"] == "rolled_back":
        return row.copy()
    row["status"] = "rolled_back"
    row["rolled_back_at"] = _iso_from_epoch(_now_epoch())
    row["rollback_reason"] = reason
    installs[install_id] = row
    lease_storage.save_installs(installs)
    return row.copy()


def reset_state_for_tests() -> None:
    lease_storage.reset_for_tests()
