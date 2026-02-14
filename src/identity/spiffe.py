"""SPIFFE/SPIRE Credential Provider — SPIFFE ID generation and X.509 SVID issuance.

Generates SPIFFE IDs for agents and issues X.509 SVIDs (SPIFFE Verifiable
Identity Documents) for mutual TLS authentication between agents.

Note: This module generates SPIFFE-compatible identifiers and self-signed
certificates. Production deployment requires integration with a SPIRE server
for proper CA-signed SVIDs.
"""
from __future__ import annotations

import hashlib
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

_log = logging.getLogger("agenthub.spiffe")

# Default SPIFFE trust domain
DEFAULT_TRUST_DOMAIN = "agenthub.local"
SPIFFE_ID_PREFIX = "spiffe://"


def _trust_domain() -> str:
    return os.getenv("AGENTHUB_SPIFFE_TRUST_DOMAIN", DEFAULT_TRUST_DOMAIN)


def generate_spiffe_id(
    *,
    agent_id: str,
    workload_path: str | None = None,
) -> str:
    """Generate a SPIFFE ID for an agent.

    Format: spiffe://<trust-domain>/agent/<agent_id>[/<workload_path>]
    """
    domain = _trust_domain()
    # Sanitize agent_id for URI path (replace special chars)
    safe_id = agent_id.replace("@", "").replace(":", "/")
    base = f"{SPIFFE_ID_PREFIX}{domain}/agent/{safe_id}"
    if workload_path:
        base = f"{base}/{workload_path}"
    return base


def generate_svid(
    *,
    agent_id: str,
    spiffe_id: str | None = None,
    ttl_hours: int = 24,
) -> dict[str, Any]:
    """Generate a self-signed X.509 SVID for an agent.

    In production, this would be replaced by SPIRE workload API attestation.
    Returns a dict with the SVID metadata (cert/key generation requires
    cryptography library).
    """
    effective_spiffe_id = spiffe_id or generate_spiffe_id(agent_id=agent_id)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=ttl_hours)
    serial = uuid.uuid4().hex[:16]

    # Generate a deterministic fingerprint for the SVID
    fp_input = f"{effective_spiffe_id}|{serial}|{now.isoformat()}"
    fingerprint = hashlib.sha256(fp_input.encode("utf-8")).hexdigest()

    _log.info("SVID generated: spiffe_id=%s serial=%s", effective_spiffe_id, serial)

    return {
        "spiffe_id": effective_spiffe_id,
        "serial_number": serial,
        "subject": f"CN={agent_id},O=AgentHub",
        "issuer": f"CN=AgentHub CA,O=AgentHub",
        "not_before": now.isoformat(),
        "not_after": expires.isoformat(),
        "fingerprint_sha256": fingerprint,
        "key_usage": ["digital_signature", "key_encipherment"],
        "extended_key_usage": ["server_auth", "client_auth"],
        "san_uri": [effective_spiffe_id],
        "trust_domain": _trust_domain(),
        "note": "self-signed stub — production requires SPIRE CA",
    }


def verify_spiffe_id(spiffe_id: str) -> dict[str, Any]:
    """Validate a SPIFFE ID format and extract components."""
    if not spiffe_id.startswith(SPIFFE_ID_PREFIX):
        return {"valid": False, "reason": "missing spiffe:// prefix"}

    path = spiffe_id[len(SPIFFE_ID_PREFIX):]
    parts = path.split("/", 1)
    if len(parts) < 2:
        return {"valid": False, "reason": "missing workload path"}

    trust_domain = parts[0]
    workload = parts[1]

    if not trust_domain:
        return {"valid": False, "reason": "empty trust domain"}
    if not workload:
        return {"valid": False, "reason": "empty workload path"}

    expected_domain = _trust_domain()
    domain_match = trust_domain == expected_domain

    return {
        "valid": True,
        "spiffe_id": spiffe_id,
        "trust_domain": trust_domain,
        "workload_path": workload,
        "trust_domain_match": domain_match,
    }


def generate_bundle(agent_ids: list[str]) -> dict[str, Any]:
    """Generate a SPIFFE trust bundle containing SVIDs for multiple agents.

    In production, this would be served by the SPIRE server's bundle endpoint.
    """
    entries: list[dict[str, Any]] = []
    for agent_id in agent_ids:
        spiffe_id = generate_spiffe_id(agent_id=agent_id)
        entries.append({
            "spiffe_id": spiffe_id,
            "agent_id": agent_id,
        })

    return {
        "trust_domain": _trust_domain(),
        "bundle_format": "spiffe-bundle-v1",
        "entries": entries,
        "entry_count": len(entries),
    }
