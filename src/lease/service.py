from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

LEASES: dict[str, dict[str, Any]] = {}


def _now_epoch() -> int:
    return int(datetime.now(UTC).timestamp())


def _iso_from_epoch(value: int) -> str:
    return datetime.fromtimestamp(value, tz=UTC).isoformat()


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
    LEASES[lease_id] = record
    return _normalize_status(record.copy(), now)


def get_lease(lease_id: str, owner: str) -> dict[str, Any]:
    if lease_id not in LEASES:
        raise KeyError("lease not found")
    row = LEASES[lease_id]
    if row["owner"] != owner:
        raise PermissionError("owner mismatch")
    _normalize_status(row)
    return row.copy()


def promote_lease(
    lease_id: str,
    owner: str,
    signature: str,
    attestation_hash: str,
    policy_approved: bool,
) -> dict[str, Any]:
    if lease_id not in LEASES:
        raise KeyError("lease not found")
    row = LEASES[lease_id]
    if row["owner"] != owner:
        raise PermissionError("owner mismatch")

    _normalize_status(row)
    if row["status"] == "expired":
        raise ValueError("lease expired")
    if row["status"] == "promoted":
        return row.copy()
    if row["status"] != "active":
        raise ValueError("lease is not active")
    if not policy_approved:
        raise PermissionError("policy approval required")
    if attestation_hash != row["attestation_hash"]:
        raise PermissionError("attestation hash mismatch")
    if signature != _expected_signature(attestation_hash=attestation_hash, owner=owner):
        raise PermissionError("invalid attestation signature")

    row["status"] = "promoted"
    row["promotion"] = {
        "promoted_at": _iso_from_epoch(_now_epoch()),
        "installed_ref": f"{row['requester_agent_id']}::{row['capability_ref']}",
        "attestation_hash": attestation_hash,
    }
    return row.copy()
