from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from typing import Any

from src.common.time import iso_from_epoch, utc_now_epoch
from src.identity.constants import (
    DEFAULT_CREDENTIAL_TTL_SECONDS,
    MAX_CREDENTIAL_TTL_SECONDS,
    MIN_CREDENTIAL_TTL_SECONDS,
    STATUS_ACTIVE,
)
from src.identity.storage import IDENTITY_STORAGE

TRUST_LEVEL_VERIFIED = "verified"
TRUST_LEVEL_PROVISIONAL = "provisional"
TRUST_LEVEL_REVOKED = "revoked"
VALID_TRUST_LEVELS = {TRUST_LEVEL_VERIFIED, TRUST_LEVEL_PROVISIONAL, TRUST_LEVEL_REVOKED}


def _signing_secret() -> bytes:
    secret = os.getenv("AGENTHUB_IDENTITY_SIGNING_SECRET")
    if secret is None or not secret.strip():
        raise RuntimeError("AGENTHUB_IDENTITY_SIGNING_SECRET is required")
    return secret.encode("utf-8")


def _sign_attestation(payload: str) -> str:
    return hmac.new(_signing_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()


# --- Trust Registry ---


def register_trusted_domain(
    *,
    domain_id: str,
    display_name: str,
    trust_level: str = TRUST_LEVEL_VERIFIED,
    public_key_pem: str | None = None,
    allowed_scopes: list[str] | None = None,
    registered_by: str,
) -> dict[str, Any]:
    """Register a trusted domain in the trust registry."""
    if trust_level not in VALID_TRUST_LEVELS:
        raise ValueError(f"invalid trust_level: {trust_level}")

    IDENTITY_STORAGE._ensure_ready()
    conn = IDENTITY_STORAGE._conn
    assert conn is not None

    scopes_json = json.dumps(sorted(allowed_scopes or []))

    try:
        with conn:
            conn.execute(
                """
                INSERT INTO trusted_domains(
                    domain_id, display_name, trust_level, public_key_pem,
                    allowed_scopes_json, registered_by
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (domain_id, display_name, trust_level, public_key_pem, scopes_json, registered_by),
            )
    except Exception as exc:
        if "UNIQUE" in str(exc):
            raise ValueError(f"domain already registered: {domain_id}") from exc
        raise

    return get_trusted_domain(domain_id)


def get_trusted_domain(domain_id: str) -> dict[str, Any]:
    """Get a trusted domain from the registry."""
    IDENTITY_STORAGE._ensure_ready()
    conn = IDENTITY_STORAGE._conn
    assert conn is not None

    row = conn.execute(
        "SELECT * FROM trusted_domains WHERE domain_id = ?",
        (domain_id,),
    ).fetchone()
    if row is None:
        raise KeyError(f"trusted domain not found: {domain_id}")

    return {
        "domain_id": str(row["domain_id"]),
        "display_name": str(row["display_name"]),
        "trust_level": str(row["trust_level"]),
        "public_key_pem": row["public_key_pem"],
        "allowed_scopes": json.loads(row["allowed_scopes_json"]),
        "registered_by": str(row["registered_by"]),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }


_MAX_DOMAINS_QUERY = 10_000


def list_trusted_domains() -> list[dict[str, Any]]:
    """List trusted domains (capped for safety)."""
    IDENTITY_STORAGE._ensure_ready()
    conn = IDENTITY_STORAGE._conn
    assert conn is not None

    rows = conn.execute(
        "SELECT * FROM trusted_domains ORDER BY created_at DESC LIMIT ?",
        (_MAX_DOMAINS_QUERY,),
    ).fetchall()
    results: list[dict[str, Any]] = []
    for row in rows:
        results.append({
            "domain_id": str(row["domain_id"]),
            "display_name": str(row["display_name"]),
            "trust_level": str(row["trust_level"]),
            "allowed_scopes": json.loads(row["allowed_scopes_json"]),
            "registered_by": str(row["registered_by"]),
            "created_at": str(row["created_at"]),
        })
    return results


# --- Agent Attestation ---


def create_agent_attestation(
    *,
    agent_id: str,
    domain_id: str,
    claims: dict[str, str] | None = None,
    ttl_seconds: int = DEFAULT_CREDENTIAL_TTL_SECONDS,
    owner: str,
) -> dict[str, Any]:
    """Create an attestation binding an agent identity to a trusted domain."""
    # Verify agent exists and is active
    identity = IDENTITY_STORAGE.get_identity(agent_id)
    if identity["status"] != STATUS_ACTIVE:
        raise PermissionError(f"agent is {identity['status']}")
    if identity["owner"] != owner:
        raise PermissionError("owner mismatch")

    # Verify domain is trusted
    domain = get_trusted_domain(domain_id)
    if domain["trust_level"] == TRUST_LEVEL_REVOKED:
        raise PermissionError(f"domain trust is revoked: {domain_id}")

    ttl = max(MIN_CREDENTIAL_TTL_SECONDS, min(int(ttl_seconds), MAX_CREDENTIAL_TTL_SECONDS))
    now = utc_now_epoch()
    attestation_id = f"att-{uuid.uuid4().hex[:16]}"
    claims_json = json.dumps(claims or {}, sort_keys=True)

    # Create signed attestation
    payload = json.dumps(
        {"aid": attestation_id, "agent": agent_id, "dom": domain_id, "exp": now + ttl},
        sort_keys=True,
        separators=(",", ":"),
    )
    signature = _sign_attestation(payload)

    IDENTITY_STORAGE._ensure_ready()
    conn = IDENTITY_STORAGE._conn
    assert conn is not None

    with conn:
        conn.execute(
            """
            INSERT INTO agent_attestations(
                attestation_id, agent_id, domain_id, claims_json,
                issued_at_epoch, expires_at_epoch, signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (attestation_id, agent_id, domain_id, claims_json, now, now + ttl, signature),
        )

    return {
        "attestation_id": attestation_id,
        "agent_id": agent_id,
        "domain_id": domain_id,
        "claims": claims or {},
        "issued_at": iso_from_epoch(now),
        "expires_at": iso_from_epoch(now + ttl),
        "signature": signature,
    }


def verify_agent_attestation(attestation_id: str) -> dict[str, Any]:
    """Verify an agent attestation is valid."""
    IDENTITY_STORAGE._ensure_ready()
    conn = IDENTITY_STORAGE._conn
    assert conn is not None

    row = conn.execute(
        "SELECT * FROM agent_attestations WHERE attestation_id = ?",
        (attestation_id,),
    ).fetchone()
    if row is None:
        raise KeyError(f"attestation not found: {attestation_id}")

    now = utc_now_epoch()
    expires = int(row["expires_at_epoch"])
    if expires < now:
        raise PermissionError("attestation expired")

    # Verify signature
    payload = json.dumps(
        {"aid": attestation_id, "agent": str(row["agent_id"]), "dom": str(row["domain_id"]), "exp": expires},
        sort_keys=True,
        separators=(",", ":"),
    )
    expected_sig = _sign_attestation(payload)
    if not hmac.compare_digest(str(row["signature"]), expected_sig):
        raise PermissionError("invalid attestation signature")

    # Verify agent is still active
    identity = IDENTITY_STORAGE.get_identity(str(row["agent_id"]))
    if identity["status"] != STATUS_ACTIVE:
        raise PermissionError(f"agent is {identity['status']}")

    # Verify domain is still trusted
    domain = get_trusted_domain(str(row["domain_id"]))
    if domain["trust_level"] == TRUST_LEVEL_REVOKED:
        raise PermissionError("domain trust has been revoked")

    return {
        "valid": True,
        "attestation_id": attestation_id,
        "agent_id": str(row["agent_id"]),
        "domain_id": str(row["domain_id"]),
        "claims": json.loads(row["claims_json"]),
        "expires_at": iso_from_epoch(expires),
    }
