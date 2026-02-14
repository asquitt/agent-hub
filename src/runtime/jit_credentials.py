"""JIT Credential Binding — auto-issue on sandbox provision, auto-revoke on terminate.

Provides just-in-time credential management for sandboxed agent execution.
Credentials are automatically scoped to the sandbox lifecycle and revoked
when the sandbox terminates.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from src.common.time import utc_now_epoch
from src.identity.constants import CREDENTIAL_TYPE_JWT, MAX_CREDENTIAL_TTL_SECONDS
from src.identity.storage import IDENTITY_STORAGE

_log = logging.getLogger("agenthub.jit_credentials")

# Default JIT credential TTL: 1 hour (sandbox-scoped)
DEFAULT_JIT_TTL_SECONDS = 3600

# Default scopes for JIT credentials
DEFAULT_JIT_SCOPES = ["runtime.execute", "read"]


def issue_jit_credential(
    *,
    agent_id: str,
    sandbox_id: str,
    scopes: list[str] | None = None,
    ttl_seconds: int = DEFAULT_JIT_TTL_SECONDS,
) -> dict[str, Any]:
    """Issue a JIT credential bound to a sandbox lifecycle.

    The credential is automatically scoped to the sandbox and should be
    revoked when the sandbox terminates.

    Raises KeyError if agent_id is not found in identity store.
    """
    # Verify agent exists
    identity = IDENTITY_STORAGE.get_identity(agent_id)

    now = utc_now_epoch()
    ttl = min(ttl_seconds, MAX_CREDENTIAL_TTL_SECONDS)
    credential_id = f"jit-{sandbox_id}-{uuid.uuid4().hex[:8]}"
    effective_scopes = scopes or list(DEFAULT_JIT_SCOPES)

    # Create a credential hash binding sandbox_id for traceability
    import hashlib
    binding = f"{credential_id}|{sandbox_id}|{agent_id}|{now}"
    credential_hash = hashlib.sha256(binding.encode("utf-8")).hexdigest()

    IDENTITY_STORAGE.insert_credential(
        credential_id=credential_id,
        agent_id=agent_id,
        credential_hash=credential_hash,
        scopes=effective_scopes,
        issued_at_epoch=now,
        expires_at_epoch=now + ttl,
        rotation_parent_id=None,
    )

    _log.info(
        "JIT credential issued: credential_id=%s agent_id=%s sandbox_id=%s ttl=%d",
        credential_id, agent_id, sandbox_id, ttl,
    )

    return {
        "credential_id": credential_id,
        "agent_id": agent_id,
        "sandbox_id": sandbox_id,
        "scopes": effective_scopes,
        "issued_at_epoch": now,
        "expires_at_epoch": now + ttl,
        "owner": identity["owner"],
    }


def revoke_jit_credential(
    *,
    credential_id: str,
    sandbox_id: str,
    reason: str = "sandbox_terminated",
) -> dict[str, Any]:
    """Revoke a JIT credential when its sandbox terminates.

    Returns the updated credential metadata.
    """
    try:
        credential = IDENTITY_STORAGE.update_credential_status_if_active(
            credential_id=credential_id,
            new_status="revoked",
            reason=f"jit:{reason}:sandbox={sandbox_id}",
        )
        _log.info(
            "JIT credential revoked: credential_id=%s sandbox_id=%s reason=%s",
            credential_id, sandbox_id, reason,
        )
        return dict(credential)
    except ValueError:
        # Already revoked or expired — idempotent
        _log.info(
            "JIT credential already inactive: credential_id=%s sandbox_id=%s",
            credential_id, sandbox_id,
        )
        credential = IDENTITY_STORAGE.get_credential(credential_id)
        return dict(credential)


def revoke_all_sandbox_credentials(
    *,
    agent_id: str,
    sandbox_id: str,
) -> dict[str, Any]:
    """Revoke all JIT credentials for a specific sandbox.

    Finds credentials by agent_id prefix matching sandbox_id.
    """
    prefix = f"jit-{sandbox_id}-"
    active_creds = IDENTITY_STORAGE.list_active_credentials(agent_id)
    revoked_count = 0

    for cred in active_creds:
        if cred["credential_id"].startswith(prefix):
            try:
                IDENTITY_STORAGE.update_credential_status_if_active(
                    credential_id=cred["credential_id"],
                    new_status="revoked",
                    reason=f"jit:sandbox_terminated:sandbox={sandbox_id}",
                )
                revoked_count += 1
            except ValueError:
                pass  # Already revoked

    _log.info(
        "Revoked %d JIT credentials for sandbox %s (agent %s)",
        revoked_count, sandbox_id, agent_id,
    )

    return {
        "agent_id": agent_id,
        "sandbox_id": sandbox_id,
        "revoked_count": revoked_count,
    }
