from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from typing import Any

from src.common.time import iso_from_epoch, utc_now_epoch
from src.identity.chain import attenuate_scopes, build_chain, validate_chain_depth
from src.identity.constants import (
    DEFAULT_CREDENTIAL_TTL_SECONDS,
    MAX_CREDENTIAL_TTL_SECONDS,
    MIN_CREDENTIAL_TTL_SECONDS,
    STATUS_ACTIVE,
)
from src.identity.storage import IDENTITY_STORAGE


def _signing_secret() -> bytes:
    secret = os.getenv("AGENTHUB_IDENTITY_SIGNING_SECRET")
    if secret is None or not secret.strip():
        raise RuntimeError("AGENTHUB_IDENTITY_SIGNING_SECRET is required")
    return secret.encode("utf-8")


def _sign_token(payload: str) -> str:
    return hmac.new(_signing_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_delegation_token(
    *,
    issuer_agent_id: str,
    subject_agent_id: str,
    delegated_scopes: list[str],
    ttl_seconds: int = DEFAULT_CREDENTIAL_TTL_SECONDS,
    parent_token_id: str | None = None,
    owner: str,
) -> dict[str, Any]:
    issuer_identity = IDENTITY_STORAGE.get_identity(issuer_agent_id)
    if issuer_identity["status"] != STATUS_ACTIVE:
        raise PermissionError(f"issuer agent is {issuer_identity['status']}")
    if issuer_identity["owner"] != owner:
        raise PermissionError("owner mismatch for issuer agent")

    # Validate subject exists and is active
    subject_identity = IDENTITY_STORAGE.get_identity(subject_agent_id)
    if subject_identity["status"] != STATUS_ACTIVE:
        raise PermissionError(f"subject agent is {subject_identity['status']}")

    # Determine chain depth and parent scopes
    chain_depth = 0
    parent_expires_epoch: int | None = None
    if parent_token_id:
        parent = _get_token_record(parent_token_id)
        if parent is None:
            raise ValueError(f"parent token not found: {parent_token_id}")
        if parent["revoked"]:
            raise PermissionError("parent token is revoked")
        parent_expires_epoch = int(parent["expires_at_epoch"])
        if parent_expires_epoch < utc_now_epoch():
            raise PermissionError("parent token is expired")
        chain_depth = int(parent["chain_depth"]) + 1
        validate_chain_depth(chain_depth)
        parent_scopes = json.loads(parent["delegated_scopes_json"])
        effective_scopes = attenuate_scopes(parent_scopes, delegated_scopes)
    else:
        # Root delegation: scopes are validated against issuer's active credentials
        issuer_creds = IDENTITY_STORAGE.list_active_credentials(issuer_agent_id)
        if not issuer_creds:
            raise PermissionError("issuer has no active credentials")
        all_issuer_scopes: set[str] = set()
        for cred in issuer_creds:
            all_issuer_scopes.update(cred["scopes"])
        effective_scopes = attenuate_scopes(sorted(all_issuer_scopes), delegated_scopes)

    ttl = max(MIN_CREDENTIAL_TTL_SECONDS, min(int(ttl_seconds), MAX_CREDENTIAL_TTL_SECONDS))
    now = utc_now_epoch()
    token_id = f"dtk-{uuid.uuid4().hex[:16]}"

    # Token cannot outlive parent
    if parent_expires_epoch is not None:
        max_expires = min(now + ttl, parent_expires_epoch)
    else:
        max_expires = now + ttl

    _insert_token_record(
        token_id=token_id,
        issuer_agent_id=issuer_agent_id,
        subject_agent_id=subject_agent_id,
        delegated_scopes=effective_scopes,
        issued_at_epoch=now,
        expires_at_epoch=max_expires,
        parent_token_id=parent_token_id,
        chain_depth=chain_depth,
    )

    # Create signed token string
    token_payload = json.dumps(
        {"tid": token_id, "sub": subject_agent_id, "iss": issuer_agent_id, "exp": max_expires},
        sort_keys=True,
        separators=(",", ":"),
    )
    signature = _sign_token(token_payload)
    signed_token = f"{token_id}.{signature}"

    return {
        "token_id": token_id,
        "signed_token": signed_token,
        "issuer_agent_id": issuer_agent_id,
        "subject_agent_id": subject_agent_id,
        "delegated_scopes": effective_scopes,
        "issued_at": iso_from_epoch(now),
        "expires_at": iso_from_epoch(max_expires),
        "chain_depth": chain_depth,
        "parent_token_id": parent_token_id,
    }


def verify_delegation_token(signed_token: str) -> dict[str, Any]:
    try:
        token_id, signature = signed_token.split(".", 1)
    except ValueError as exc:
        raise PermissionError("invalid delegation token format") from exc

    record = _get_token_record(token_id)
    if record is None:
        raise PermissionError("delegation token not found")

    if record["revoked"]:
        raise PermissionError("delegation token is revoked")

    now = utc_now_epoch()
    if int(record["expires_at_epoch"]) < now:
        raise PermissionError("delegation token expired")

    # Verify signature
    token_payload = json.dumps(
        {
            "tid": token_id,
            "sub": str(record["subject_agent_id"]),
            "iss": str(record["issuer_agent_id"]),
            "exp": int(record["expires_at_epoch"]),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    expected_sig = _sign_token(token_payload)
    if not hmac.compare_digest(signature, expected_sig):
        raise PermissionError("invalid delegation token signature")

    # Verify the full chain is valid (no revoked parents)
    _verify_chain_integrity(record)

    scopes = json.loads(record["delegated_scopes_json"])
    return {
        "valid": True,
        "token_id": token_id,
        "issuer_agent_id": str(record["issuer_agent_id"]),
        "subject_agent_id": str(record["subject_agent_id"]),
        "delegated_scopes": scopes,
        "expires_at_epoch": int(record["expires_at_epoch"]),
        "chain_depth": int(record["chain_depth"]),
    }


def get_delegation_chain(token_id: str) -> dict[str, Any]:
    record = _get_token_record(token_id)
    if record is None:
        raise KeyError(f"delegation token not found: {token_id}")

    chain_records: list[dict[str, Any]] = []
    current = record
    while current is not None:
        scopes = json.loads(current["delegated_scopes_json"])
        chain_records.append({
            "token_id": str(current["token_id"]),
            "issuer_agent_id": str(current["issuer_agent_id"]),
            "subject_agent_id": str(current["subject_agent_id"]),
            "delegated_scopes": scopes,
            "chain_depth": int(current["chain_depth"]),
            "revoked": bool(current["revoked"]),
            "expires_at": iso_from_epoch(int(current["expires_at_epoch"])),
        })
        parent_id = current["parent_token_id"]
        if parent_id:
            current = _get_token_record(str(parent_id))
        else:
            current = None

    ordered = build_chain(chain_records)
    return {
        "token_id": token_id,
        "chain": ordered,
        "chain_depth": int(record["chain_depth"]),
        "effective_scopes": json.loads(record["delegated_scopes_json"]),
    }


def revoke_delegation_token(token_id: str, owner: str) -> dict[str, Any]:
    record = _get_token_record(token_id)
    if record is None:
        raise KeyError(f"delegation token not found: {token_id}")

    issuer_identity = IDENTITY_STORAGE.get_identity(str(record["issuer_agent_id"]))
    if issuer_identity["owner"] != owner:
        raise PermissionError("owner mismatch")

    now = utc_now_epoch()
    conn = IDENTITY_STORAGE._conn
    assert conn is not None
    with conn:
        conn.execute(
            "UPDATE delegation_tokens SET revoked = 1, revoked_at = ? WHERE token_id = ?",
            (iso_from_epoch(now), token_id),
        )
        # Cascade: revoke all child tokens
        cascade_count = _cascade_revoke(token_id, now)

    return {
        "token_id": token_id,
        "revoked": True,
        "revoked_at": iso_from_epoch(now),
        "cascade_count": cascade_count,
    }


# --- Internal helpers ---


def _get_token_record(token_id: str) -> dict[str, Any] | None:
    IDENTITY_STORAGE._ensure_ready()
    conn = IDENTITY_STORAGE._conn
    assert conn is not None
    row = conn.execute(
        "SELECT * FROM delegation_tokens WHERE token_id = ?",
        (token_id,),
    ).fetchone()
    if row is None:
        return None
    return dict(row)


def _insert_token_record(
    *,
    token_id: str,
    issuer_agent_id: str,
    subject_agent_id: str,
    delegated_scopes: list[str],
    issued_at_epoch: int,
    expires_at_epoch: int,
    parent_token_id: str | None,
    chain_depth: int,
) -> None:
    IDENTITY_STORAGE._ensure_ready()
    conn = IDENTITY_STORAGE._conn
    assert conn is not None
    with conn:
        conn.execute(
            """
            INSERT INTO delegation_tokens(
                token_id, issuer_agent_id, subject_agent_id, delegated_scopes_json,
                issued_at_epoch, expires_at_epoch, parent_token_id, chain_depth
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token_id,
                issuer_agent_id,
                subject_agent_id,
                json.dumps(sorted(delegated_scopes)),
                issued_at_epoch,
                expires_at_epoch,
                parent_token_id,
                chain_depth,
            ),
        )


def _verify_chain_integrity(record: dict[str, Any], _depth: int = 0) -> None:
    from src.identity.constants import MAX_DELEGATION_CHAIN_DEPTH

    if _depth > MAX_DELEGATION_CHAIN_DEPTH:
        raise PermissionError("delegation chain too deep or circular")
    parent_id = record.get("parent_token_id")
    if not parent_id:
        return
    parent = _get_token_record(str(parent_id))
    if parent is None:
        raise PermissionError("delegation chain broken: parent token missing")
    if parent["revoked"]:
        raise PermissionError("delegation chain invalid: parent token revoked")
    now = utc_now_epoch()
    if int(parent["expires_at_epoch"]) < now:
        raise PermissionError("delegation chain invalid: parent token expired")
    _verify_chain_integrity(parent, _depth + 1)


def _cascade_revoke(parent_token_id: str, now_epoch: int) -> int:
    conn = IDENTITY_STORAGE._conn
    assert conn is not None
    children = conn.execute(
        "SELECT token_id FROM delegation_tokens WHERE parent_token_id = ? AND revoked = 0",
        (parent_token_id,),
    ).fetchall()
    count = 0
    for child in children:
        child_id = str(child["token_id"])
        conn.execute(
            "UPDATE delegation_tokens SET revoked = 1, revoked_at = ? WHERE token_id = ?",
            (iso_from_epoch(now_epoch), child_id),
        )
        count += 1
        count += _cascade_revoke(child_id, now_epoch)
    return count
