"""Capability-Based Security Tokens — Biscuit-inspired with caveats and attenuation.

Issues capability tokens that carry embedded authorization facts and caveats.
Tokens support:
- Scope attenuation (child tokens can only reduce, never expand permissions)
- Caveats (time-bound, IP-bound, resource-bound constraints)
- Third-party verification blocks
- HMAC-SHA256 signatures with chained blocks
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

_log = logging.getLogger("agenthub.capability_tokens")

_DEFAULT_TTL_SECONDS = 3600
_MAX_BLOCKS = 10


def _signing_secret() -> bytes:
    secret = os.getenv("AGENTHUB_IDENTITY_SIGNING_SECRET", "")
    if not secret:
        raise PermissionError("AGENTHUB_IDENTITY_SIGNING_SECRET not configured")
    return secret.encode("utf-8")


def _sign_block(block_data: str, secret: bytes) -> str:
    return hmac.new(secret, block_data.encode("utf-8"), hashlib.sha256).hexdigest()


def _block_key(parent_sig: str, secret: bytes) -> bytes:
    """Derive a child block signing key from parent signature."""
    return hmac.new(secret, parent_sig.encode("utf-8"), hashlib.sha256).digest()


# ── Caveat types ────────────────────────────────────────────────────

CAVEAT_TIME = "time"
CAVEAT_IP = "ip"
CAVEAT_RESOURCE = "resource"
CAVEAT_SCOPE = "scope"
CAVEAT_AGENT = "agent"
VALID_CAVEAT_TYPES = {CAVEAT_TIME, CAVEAT_IP, CAVEAT_RESOURCE, CAVEAT_SCOPE, CAVEAT_AGENT}


def make_time_caveat(*, not_after: float) -> dict[str, Any]:
    """Create a time-bound caveat (epoch timestamp)."""
    return {"type": CAVEAT_TIME, "not_after": not_after}


def make_ip_caveat(*, allowed_ips: list[str]) -> dict[str, Any]:
    """Create an IP-bound caveat."""
    return {"type": CAVEAT_IP, "allowed_ips": allowed_ips}


def make_resource_caveat(*, resources: list[str]) -> dict[str, Any]:
    """Create a resource-bound caveat."""
    return {"type": CAVEAT_RESOURCE, "resources": resources}


def make_scope_caveat(*, scopes: list[str]) -> dict[str, Any]:
    """Create a scope-restriction caveat."""
    return {"type": CAVEAT_SCOPE, "scopes": scopes}


def make_agent_caveat(*, agent_ids: list[str]) -> dict[str, Any]:
    """Create an agent-restriction caveat."""
    return {"type": CAVEAT_AGENT, "agent_ids": agent_ids}


# ── Token operations ───────────────────────────────────────────────


def issue_capability_token(
    *,
    issuer_agent_id: str,
    subject_agent_id: str,
    scopes: list[str],
    caveats: list[dict[str, Any]] | None = None,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    facts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Issue a new capability token with an authority block."""
    now = time.time()
    token_id = f"cap-{uuid.uuid4().hex[:16]}"

    # Validate caveats
    resolved_caveats = list(caveats or [])
    for c in resolved_caveats:
        if c.get("type") not in VALID_CAVEAT_TYPES:
            raise ValueError(f"unknown caveat type: {c.get('type')}")

    # Always add a time caveat
    resolved_caveats.append(make_time_caveat(not_after=now + ttl_seconds))

    authority_block: dict[str, Any] = {
        "block_index": 0,
        "issuer": issuer_agent_id,
        "subject": subject_agent_id,
        "scopes": sorted(scopes),
        "caveats": resolved_caveats,
        "facts": facts or {},
        "issued_at": now,
    }

    secret = _signing_secret()
    block_data = json.dumps(authority_block, sort_keys=True, separators=(",", ":"))
    authority_sig = _sign_block(block_data, secret)

    token: dict[str, Any] = {
        "token_id": token_id,
        "version": 1,
        "authority": authority_block,
        "blocks": [],
        "signatures": [authority_sig],
    }

    _log.info(
        "capability token issued: token_id=%s issuer=%s subject=%s scopes=%s",
        token_id, issuer_agent_id, subject_agent_id, scopes,
    )
    return token


def attenuate_token(
    token: dict[str, Any],
    *,
    scopes: list[str] | None = None,
    caveats: list[dict[str, Any]] | None = None,
    attenuator_agent_id: str,
) -> dict[str, Any]:
    """Append an attenuation block that further restricts the token.

    Scopes can only be reduced (subset of parent). Caveats can only be added.
    """
    existing_blocks = token.get("blocks", [])
    if len(existing_blocks) >= _MAX_BLOCKS - 1:
        raise ValueError(f"maximum block count ({_MAX_BLOCKS}) reached")

    # Determine effective scopes from the last block (or authority)
    if existing_blocks:
        parent_scopes = set(existing_blocks[-1].get("scopes", []))
    else:
        parent_scopes = set(token["authority"].get("scopes", []))

    new_scopes = sorted(scopes) if scopes else sorted(parent_scopes)
    new_scope_set = set(new_scopes)

    # Wildcard parent allows any child scopes
    if "*" not in parent_scopes:
        excess = new_scope_set - parent_scopes
        if excess:
            raise PermissionError(f"scope escalation denied: {sorted(excess)} not in parent scopes")

    block_index = len(existing_blocks) + 1
    new_block: dict[str, Any] = {
        "block_index": block_index,
        "attenuator": attenuator_agent_id,
        "scopes": new_scopes,
        "caveats": list(caveats or []),
        "attenuated_at": time.time(),
    }

    # Validate new caveats
    for c in new_block["caveats"]:
        if c.get("type") not in VALID_CAVEAT_TYPES:
            raise ValueError(f"unknown caveat type: {c.get('type')}")

    # Sign with derived key
    secret = _signing_secret()
    parent_sig = token["signatures"][-1]
    derived_key = _block_key(parent_sig, secret)
    block_data = json.dumps(new_block, sort_keys=True, separators=(",", ":"))
    block_sig = _sign_block(block_data, derived_key)

    # Return new token (immutable — don't modify original)
    attenuated = {
        "token_id": token["token_id"],
        "version": token["version"],
        "authority": token["authority"],
        "blocks": existing_blocks + [new_block],
        "signatures": token["signatures"] + [block_sig],
    }

    _log.info(
        "capability token attenuated: token_id=%s block=%d by=%s",
        token["token_id"], block_index, attenuator_agent_id,
    )
    return attenuated


def verify_capability_token(
    token: dict[str, Any],
    *,
    required_scope: str | None = None,
    source_ip: str | None = None,
    resource: str | None = None,
) -> dict[str, Any]:
    """Verify a capability token: signatures, caveats, and optional requirements.

    Returns a result dict with valid=True/False and effective scopes.
    """
    secret = _signing_secret()

    # Step 1: Verify authority block signature
    authority = token.get("authority", {})
    authority_data = json.dumps(authority, sort_keys=True, separators=(",", ":"))
    expected_authority_sig = _sign_block(authority_data, secret)

    sigs = token.get("signatures", [])
    if not sigs or sigs[0] != expected_authority_sig:
        return {"valid": False, "reason": "authority block signature mismatch"}

    # Step 2: Verify each attenuation block signature
    blocks = token.get("blocks", [])
    for i, block in enumerate(blocks):
        parent_sig = sigs[i]
        derived_key = _block_key(parent_sig, secret)
        block_data = json.dumps(block, sort_keys=True, separators=(",", ":"))
        expected_sig = _sign_block(block_data, derived_key)
        if i + 1 >= len(sigs) or sigs[i + 1] != expected_sig:
            return {"valid": False, "reason": f"block {i + 1} signature mismatch"}

    # Step 3: Collect all caveats (authority + all blocks)
    all_caveats: list[dict[str, Any]] = list(authority.get("caveats", []))
    for block in blocks:
        all_caveats.extend(block.get("caveats", []))

    # Step 4: Evaluate caveats
    now = time.time()
    for caveat in all_caveats:
        ctype = caveat.get("type")
        if ctype == CAVEAT_TIME:
            if now > caveat.get("not_after", 0):
                return {"valid": False, "reason": "token expired (time caveat)"}
        elif ctype == CAVEAT_IP and source_ip:
            if source_ip not in caveat.get("allowed_ips", []):
                return {"valid": False, "reason": f"source IP {source_ip} not in allowed IPs"}
        elif ctype == CAVEAT_RESOURCE and resource:
            if resource not in caveat.get("resources", []):
                return {"valid": False, "reason": f"resource {resource} not permitted"}
        elif ctype == CAVEAT_AGENT:
            # Agent caveat checked against subject
            allowed = caveat.get("agent_ids", [])
            if authority.get("subject") not in allowed:
                return {"valid": False, "reason": "subject agent not in allowed agent IDs"}

    # Step 5: Determine effective scopes (most attenuated, ignoring third-party blocks)
    effective_scopes = sorted(authority.get("scopes", []))
    for block in blocks:
        if "third_party_verifier" in block:
            continue  # Third-party blocks don't modify scopes
        block_scopes = block.get("scopes", [])
        if block_scopes:
            effective_scopes = sorted(block_scopes)

    # Step 6: Check required scope
    if required_scope and required_scope not in effective_scopes and "*" not in effective_scopes:
        return {"valid": False, "reason": f"missing required scope: {required_scope}"}

    return {
        "valid": True,
        "token_id": token.get("token_id", ""),
        "issuer": authority.get("issuer", ""),
        "subject": authority.get("subject", ""),
        "effective_scopes": effective_scopes,
        "block_count": len(blocks) + 1,
        "caveat_count": len(all_caveats),
    }


def add_third_party_block(
    token: dict[str, Any],
    *,
    verifier_id: str,
    verification_data: dict[str, Any],
) -> dict[str, Any]:
    """Add a third-party verification block to a token.

    Third-party blocks attest to external facts (e.g., identity verification,
    compliance checks) without modifying scopes.
    """
    existing_blocks = token.get("blocks", [])
    if len(existing_blocks) >= _MAX_BLOCKS - 1:
        raise ValueError(f"maximum block count ({_MAX_BLOCKS}) reached")

    block_index = len(existing_blocks) + 1
    tp_block: dict[str, Any] = {
        "block_index": block_index,
        "third_party_verifier": verifier_id,
        "verification_data": verification_data,
        "verified_at": time.time(),
        "scopes": [],
        "caveats": [],
    }

    secret = _signing_secret()
    parent_sig = token["signatures"][-1]
    derived_key = _block_key(parent_sig, secret)
    block_data = json.dumps(tp_block, sort_keys=True, separators=(",", ":"))
    block_sig = _sign_block(block_data, derived_key)

    result = {
        "token_id": token["token_id"],
        "version": token["version"],
        "authority": token["authority"],
        "blocks": existing_blocks + [tp_block],
        "signatures": token["signatures"] + [block_sig],
    }

    _log.info(
        "third-party block added: token_id=%s verifier=%s",
        token["token_id"], verifier_id,
    )
    return result
