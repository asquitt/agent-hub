from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import uuid
from typing import Any

from src.common.time import iso_from_epoch, utc_now_epoch
from src.identity.constants import (
    CRED_STATUS_ACTIVE,
    CRED_STATUS_REVOKED,
    CRED_STATUS_ROTATED,
    DEFAULT_CREDENTIAL_TTL_SECONDS,
    MAX_CREDENTIAL_TTL_SECONDS,
    MIN_CREDENTIAL_TTL_SECONDS,
    SECRET_BYTE_LENGTH,
    STATUS_ACTIVE,
    WILDCARD_SCOPE,
)
from src.identity.storage import IDENTITY_STORAGE
from src.identity.types import AgentCredential, CredentialIssuanceResult, CredentialVerification


def _signing_secret() -> bytes:
    secret = os.getenv("AGENTHUB_IDENTITY_SIGNING_SECRET")
    if secret is None or not secret.strip():
        raise RuntimeError("AGENTHUB_IDENTITY_SIGNING_SECRET is required")
    return secret.encode("utf-8")


def _hash_secret(raw_secret: str) -> str:
    return hmac.new(_signing_secret(), raw_secret.encode("utf-8"), hashlib.sha256).hexdigest()


def _generate_secret() -> str:
    return secrets.token_urlsafe(SECRET_BYTE_LENGTH)


def issue_credential(
    *,
    agent_id: str,
    scopes: list[str],
    ttl_seconds: int = DEFAULT_CREDENTIAL_TTL_SECONDS,
    owner: str,
) -> CredentialIssuanceResult:
    identity = IDENTITY_STORAGE.get_identity(agent_id)
    if identity["status"] != STATUS_ACTIVE:
        raise PermissionError(f"agent identity is {identity['status']}, cannot issue credential")
    if identity["owner"] != owner:
        raise PermissionError("owner mismatch: cannot issue credential for agent owned by another")

    ttl = max(MIN_CREDENTIAL_TTL_SECONDS, min(int(ttl_seconds), MAX_CREDENTIAL_TTL_SECONDS))
    now = utc_now_epoch()
    credential_id = f"cred-{uuid.uuid4().hex[:16]}"
    raw_secret = _generate_secret()
    credential_hash = _hash_secret(raw_secret)
    normalized_scopes = sorted({s.strip() for s in scopes if s.strip()})

    IDENTITY_STORAGE.insert_credential(
        credential_id=credential_id,
        agent_id=agent_id,
        credential_hash=credential_hash,
        scopes=normalized_scopes,
        issued_at_epoch=now,
        expires_at_epoch=now + ttl,
    )

    return CredentialIssuanceResult(
        credential_id=credential_id,
        agent_id=agent_id,
        secret=raw_secret,
        scopes=normalized_scopes,
        expires_at_epoch=now + ttl,
        status=CRED_STATUS_ACTIVE,
    )


def verify_credential(secret: str) -> CredentialVerification:
    credential_hash = _hash_secret(secret)
    cred = IDENTITY_STORAGE.find_credential_by_hash(credential_hash)
    if cred is None:
        raise PermissionError("invalid credential")

    now = utc_now_epoch()
    if cred["expires_at_epoch"] < now:
        raise PermissionError("credential expired")
    if cred["status"] != CRED_STATUS_ACTIVE:
        raise PermissionError(f"credential is {cred['status']}")

    identity = IDENTITY_STORAGE.get_identity(cred["agent_id"])
    if identity["status"] != STATUS_ACTIVE:
        raise PermissionError(f"agent identity is {identity['status']}")

    return CredentialVerification(
        valid=True,
        agent_id=cred["agent_id"],
        credential_id=cred["credential_id"],
        scopes=cred["scopes"],
        expires_at_epoch=cred["expires_at_epoch"],
    )


def rotate_credential(
    *,
    credential_id: str,
    owner: str,
    new_scopes: list[str] | None = None,
    new_ttl_seconds: int = DEFAULT_CREDENTIAL_TTL_SECONDS,
) -> CredentialIssuanceResult:
    old_cred = IDENTITY_STORAGE.get_credential(credential_id)
    if old_cred["status"] != CRED_STATUS_ACTIVE:
        raise ValueError(f"cannot rotate credential in status: {old_cred['status']}")

    identity = IDENTITY_STORAGE.get_identity(old_cred["agent_id"])
    if identity["owner"] != owner:
        raise PermissionError("owner mismatch")

    IDENTITY_STORAGE.update_credential_status(credential_id, CRED_STATUS_ROTATED)

    scopes = new_scopes if new_scopes is not None else old_cred["scopes"]
    ttl = max(MIN_CREDENTIAL_TTL_SECONDS, min(int(new_ttl_seconds), MAX_CREDENTIAL_TTL_SECONDS))
    now = utc_now_epoch()
    new_credential_id = f"cred-{uuid.uuid4().hex[:16]}"
    raw_secret = _generate_secret()
    credential_hash = _hash_secret(raw_secret)
    normalized_scopes = sorted({s.strip() for s in scopes if s.strip()})

    IDENTITY_STORAGE.insert_credential(
        credential_id=new_credential_id,
        agent_id=old_cred["agent_id"],
        credential_hash=credential_hash,
        scopes=normalized_scopes,
        issued_at_epoch=now,
        expires_at_epoch=now + ttl,
        rotation_parent_id=credential_id,
    )

    return CredentialIssuanceResult(
        credential_id=new_credential_id,
        agent_id=old_cred["agent_id"],
        secret=raw_secret,
        scopes=normalized_scopes,
        expires_at_epoch=now + ttl,
        status=CRED_STATUS_ACTIVE,
    )


def revoke_credential(
    *,
    credential_id: str,
    owner: str,
    reason: str = "manual_revocation",
) -> AgentCredential:
    cred = IDENTITY_STORAGE.get_credential(credential_id)
    if cred["status"] == CRED_STATUS_REVOKED:
        return cred

    identity = IDENTITY_STORAGE.get_identity(cred["agent_id"])
    if identity["owner"] != owner:
        raise PermissionError("owner mismatch")

    return IDENTITY_STORAGE.update_credential_status(credential_id, CRED_STATUS_REVOKED, reason=reason)


def get_credential_metadata(credential_id: str) -> dict[str, Any]:
    cred = IDENTITY_STORAGE.get_credential(credential_id)
    return {
        "credential_id": cred["credential_id"],
        "agent_id": cred["agent_id"],
        "scopes": cred["scopes"],
        "issued_at": iso_from_epoch(cred["issued_at_epoch"]),
        "expires_at": iso_from_epoch(cred["expires_at_epoch"]),
        "rotation_parent_id": cred["rotation_parent_id"],
        "status": cred["status"],
        "revoked_at": cred["revoked_at"],
        "revocation_reason": cred["revocation_reason"],
    }


def has_scope(granted_scopes: list[str], required_scope: str) -> bool:
    if WILDCARD_SCOPE in granted_scopes:
        return True
    return required_scope in granted_scopes
