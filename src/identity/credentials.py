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
from src.identity.storage import IDENTITY_STORAGE, ResourceAuthContext, require_resource_actor
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


def _optional_resource_actor(value: object) -> ResourceAuthContext | None:
    if not all(hasattr(value, field) for field in ("owner", "tenant_id", "agent_id")):
        return None
    return require_resource_actor(value)


def _require_scope_attenuation(actor: ResourceAuthContext, scopes: list[str]) -> None:
    allows_scope = getattr(actor, "allows_scope", None)
    if not callable(allows_scope):
        raise PermissionError("credential issuance requires explicit scope authority")
    if any(not allows_scope(scope) for scope in scopes):
        raise PermissionError("requested scopes exceed issuer authority")


def issue_credential(
    *,
    agent_id: str,
    scopes: list[str],
    ttl_seconds: int = DEFAULT_CREDENTIAL_TTL_SECONDS,
    owner: str | ResourceAuthContext,
) -> CredentialIssuanceResult:
    ttl = max(MIN_CREDENTIAL_TTL_SECONDS, min(int(ttl_seconds), MAX_CREDENTIAL_TTL_SECONDS))
    now = utc_now_epoch()
    credential_id = f"cred-{uuid.uuid4().hex[:16]}"
    raw_secret = _generate_secret()
    credential_hash = _hash_secret(raw_secret)
    normalized_scopes = sorted({s.strip() for s in scopes if s.strip()})

    actor = _optional_resource_actor(owner)
    if actor is not None:
        _require_scope_attenuation(actor, normalized_scopes)
        IDENTITY_STORAGE.insert_credential_for_actor(
            actor=actor,
            credential_id=credential_id,
            agent_id=agent_id,
            credential_hash=credential_hash,
            scopes=normalized_scopes,
            issued_at_epoch=now,
            expires_at_epoch=now + ttl,
        )
    else:
        identity = IDENTITY_STORAGE.get_identity(agent_id)
        if identity["status"] != STATUS_ACTIVE:
            raise PermissionError(f"agent identity is {identity['status']}, cannot issue credential")
        if identity["owner"] != owner:
            raise PermissionError("owner mismatch: cannot issue credential for agent owned by another")
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
    owner: str | ResourceAuthContext,
    new_scopes: list[str] | None = None,
    new_ttl_seconds: int = DEFAULT_CREDENTIAL_TTL_SECONDS,
) -> CredentialIssuanceResult:
    actor = _optional_resource_actor(owner)
    if actor is not None:
        ttl = max(MIN_CREDENTIAL_TTL_SECONDS, min(int(new_ttl_seconds), MAX_CREDENTIAL_TTL_SECONDS))
        now = utc_now_epoch()
        new_credential_id = f"cred-{uuid.uuid4().hex[:16]}"
        raw_secret = _generate_secret()
        credential_hash = _hash_secret(raw_secret)
        normalized_scopes = None
        if new_scopes is not None:
            normalized_scopes = sorted({s.strip() for s in new_scopes if s.strip()})
        current_credential = IDENTITY_STORAGE.get_credential_for_actor(credential_id, actor)
        effective_scopes = current_credential["scopes"] if normalized_scopes is None else normalized_scopes
        _require_scope_attenuation(actor, effective_scopes)
        old_cred = IDENTITY_STORAGE.rotate_credential_for_actor(
            actor=actor,
            credential_id=credential_id,
            new_credential_id=new_credential_id,
            credential_hash=credential_hash,
            scopes=effective_scopes,
            issued_at_epoch=now,
            expires_at_epoch=now + ttl,
        )
        return CredentialIssuanceResult(
            credential_id=new_credential_id,
            agent_id=old_cred["agent_id"],
            secret=raw_secret,
            scopes=effective_scopes,
            expires_at_epoch=now + ttl,
            status=CRED_STATUS_ACTIVE,
        )

    old_cred = IDENTITY_STORAGE.get_credential(credential_id)
    if old_cred["status"] != CRED_STATUS_ACTIVE:
        raise ValueError(f"cannot rotate credential in status: {old_cred['status']}")

    identity = IDENTITY_STORAGE.get_identity(old_cred["agent_id"])
    if identity["owner"] != owner:
        raise PermissionError("owner mismatch")

    # Optimistic lock: only transitions if still active (prevents revoke-rotate race)
    IDENTITY_STORAGE.update_credential_status_if_active(credential_id, CRED_STATUS_ROTATED)

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
    owner: str | ResourceAuthContext,
    reason: str = "manual_revocation",
) -> AgentCredential:
    actor = _optional_resource_actor(owner)
    if actor is not None:
        return IDENTITY_STORAGE.revoke_credential_for_actor(credential_id, actor, reason)

    cred = IDENTITY_STORAGE.get_credential(credential_id)
    if cred["status"] == CRED_STATUS_REVOKED:
        return cred

    identity = IDENTITY_STORAGE.get_identity(cred["agent_id"])
    if identity["owner"] != owner:
        raise PermissionError("owner mismatch")

    return IDENTITY_STORAGE.update_credential_status(credential_id, CRED_STATUS_REVOKED, reason=reason)


def get_credential_metadata(
    credential_id: str,
    *,
    actor: ResourceAuthContext,
) -> dict[str, Any]:
    cred = IDENTITY_STORAGE.get_credential_for_actor(credential_id, actor)
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
