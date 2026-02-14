"""Cross-Domain Federation Protocol — multi-domain agent identity federation.

Extends the federation module with:
- Federation agreements between domains
- Cross-domain identity resolution
- Federated credential verification
- Trust level negotiation
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.cross_domain")

# Trust levels for federation
TRUST_FULL = "full"
TRUST_VERIFIED = "verified"
TRUST_LIMITED = "limited"
TRUST_UNTRUSTED = "untrusted"

VALID_TRUST_LEVELS = {TRUST_FULL, TRUST_VERIFIED, TRUST_LIMITED, TRUST_UNTRUSTED}

# In-memory stores
_federation_agreements: dict[str, dict[str, Any]] = {}  # agreement_id -> agreement
_cross_domain_identities: dict[str, dict[str, Any]] = {}  # composite_key -> mapping


def _signing_secret() -> bytes:
    secret = os.getenv("AGENTHUB_IDENTITY_SIGNING_SECRET", "")
    return secret.encode("utf-8") if secret else b"default-test-key"


def create_federation_agreement(
    *,
    local_domain: str,
    remote_domain: str,
    trust_level: str = TRUST_VERIFIED,
    allowed_scopes: list[str] | None = None,
    max_delegation_depth: int = 3,
    data_residency_policy: str = "local_only",
    ttl_seconds: int = 86400 * 30,
) -> dict[str, Any]:
    """Create a federation agreement between two domains."""
    if trust_level not in VALID_TRUST_LEVELS:
        raise ValueError(f"invalid trust level: {trust_level}")

    agreement_id = f"fed-{uuid.uuid4().hex[:12]}"
    now = time.time()

    agreement: dict[str, Any] = {
        "agreement_id": agreement_id,
        "local_domain": local_domain,
        "remote_domain": remote_domain,
        "trust_level": trust_level,
        "allowed_scopes": allowed_scopes or ["read"],
        "max_delegation_depth": max_delegation_depth,
        "data_residency_policy": data_residency_policy,
        "status": "active",
        "created_at": now,
        "expires_at": now + ttl_seconds,
    }

    # Sign agreement
    canonical = json.dumps(
        {k: v for k, v in agreement.items() if k != "signature"},
        sort_keys=True,
        separators=(",", ":"),
    )
    agreement["signature"] = hmac.new(
        _signing_secret(), canonical.encode("utf-8"), hashlib.sha256,
    ).hexdigest()

    _federation_agreements[agreement_id] = agreement
    _log.info("federation agreement created: %s (%s <-> %s)", agreement_id, local_domain, remote_domain)
    return agreement


def get_federation_agreement(agreement_id: str) -> dict[str, Any]:
    """Get a federation agreement by ID."""
    agreement = _federation_agreements.get(agreement_id)
    if agreement is None:
        raise KeyError(f"federation agreement not found: {agreement_id}")
    return agreement


def list_federation_agreements(
    domain: str | None = None,
) -> list[dict[str, Any]]:
    """List all federation agreements, optionally filtered by domain."""
    results = []
    for agreement in _federation_agreements.values():
        if domain and domain not in (agreement["local_domain"], agreement["remote_domain"]):
            continue
        results.append(agreement)
    return results


def resolve_cross_domain_identity(
    *,
    agent_id: str,
    source_domain: str,
    target_domain: str,
) -> dict[str, Any]:
    """Resolve an agent identity across domains."""
    # Check for existing mapping
    key = f"{source_domain}:{agent_id}:{target_domain}"
    existing = _cross_domain_identities.get(key)
    if existing:
        return existing

    # Check for active agreement
    agreements = [
        a for a in _federation_agreements.values()
        if a["status"] == "active"
        and source_domain in (a["local_domain"], a["remote_domain"])
        and target_domain in (a["local_domain"], a["remote_domain"])
        and a["expires_at"] > time.time()
    ]

    if not agreements:
        return {
            "resolved": False,
            "agent_id": agent_id,
            "source_domain": source_domain,
            "target_domain": target_domain,
            "reason": "no active federation agreement",
        }

    agreement = agreements[0]
    federated_id = f"{source_domain}/{agent_id}@{target_domain}"
    now = time.time()

    mapping: dict[str, Any] = {
        "resolved": True,
        "agent_id": agent_id,
        "source_domain": source_domain,
        "target_domain": target_domain,
        "federated_id": federated_id,
        "trust_level": agreement["trust_level"],
        "allowed_scopes": agreement["allowed_scopes"],
        "agreement_id": agreement["agreement_id"],
        "resolved_at": now,
    }

    _cross_domain_identities[key] = mapping
    return mapping


def verify_federated_credential(
    *,
    federated_id: str,
    claimed_scopes: list[str],
    source_domain: str,
) -> dict[str, Any]:
    """Verify a federated credential against federation agreements."""
    # Find matching agreements for the source domain
    agreements = [
        a for a in _federation_agreements.values()
        if a["status"] == "active"
        and source_domain in (a["local_domain"], a["remote_domain"])
        and a["expires_at"] > time.time()
    ]

    if not agreements:
        return {
            "valid": False,
            "federated_id": federated_id,
            "reason": "no active federation agreement for source domain",
        }

    agreement = agreements[0]
    allowed = set(agreement["allowed_scopes"])

    # Check if wildcard allows all scopes
    if "*" in allowed:
        scope_ok = True
        excess_scopes: list[str] = []
    else:
        excess_scopes = [s for s in claimed_scopes if s not in allowed]
        scope_ok = len(excess_scopes) == 0

    return {
        "valid": scope_ok,
        "federated_id": federated_id,
        "trust_level": agreement["trust_level"],
        "allowed_scopes": agreement["allowed_scopes"],
        "claimed_scopes": claimed_scopes,
        "excess_scopes": excess_scopes,
        "agreement_id": agreement["agreement_id"],
    }


def revoke_federation_agreement(agreement_id: str, reason: str = "manual") -> dict[str, Any]:
    """Revoke a federation agreement."""
    agreement = _federation_agreements.get(agreement_id)
    if agreement is None:
        raise KeyError(f"federation agreement not found: {agreement_id}")

    agreement["status"] = "revoked"
    agreement["revoked_at"] = time.time()
    agreement["revoke_reason"] = reason

    _log.info("federation agreement revoked: %s reason=%s", agreement_id, reason)
    return agreement


def reset_for_tests() -> None:
    """Clear all federation data for testing."""
    _federation_agreements.clear()
    _cross_domain_identities.clear()
