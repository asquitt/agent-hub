"""Actor-bound, persisted capability tokens with attenuating caveats."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any

from src.identity.storage import (
    IDENTITY_STORAGE,
    ResourceAuthContext,
    require_resource_actor,
)
from src.identity.authority_fence import serialized_authority_mutation

_log = logging.getLogger("agenthub.capability_tokens")

_DEFAULT_TTL_SECONDS = 3600
_MAX_BLOCKS = 10
_TOKEN_VERSION = 2
_SIGNING_DOMAIN = b"agenthub-capability-v2"


def _signing_secret() -> bytes:
    secret = os.getenv("AGENTHUB_IDENTITY_SIGNING_SECRET", "")
    if not secret.strip():
        raise PermissionError("AGENTHUB_IDENTITY_SIGNING_SECRET not configured")
    return hmac.new(secret.encode("utf-8"), _SIGNING_DOMAIN, hashlib.sha256).digest()


def _sign_block(block_data: str, secret: bytes) -> str:
    return hmac.new(secret, block_data.encode("utf-8"), hashlib.sha256).hexdigest()


def _block_key(parent_sig: str, secret: bytes) -> bytes:
    """Derive a child block signing key from its parent signature."""
    return hmac.new(secret, parent_sig.encode("utf-8"), hashlib.sha256).digest()


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("capability token data must be JSON serializable") from exc


CAVEAT_TIME = "time"
CAVEAT_IP = "ip"
CAVEAT_RESOURCE = "resource"
CAVEAT_SCOPE = "scope"
CAVEAT_AGENT = "agent"
VALID_CAVEAT_TYPES = {
    CAVEAT_TIME,
    CAVEAT_IP,
    CAVEAT_RESOURCE,
    CAVEAT_SCOPE,
    CAVEAT_AGENT,
}


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


def _required_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} is required")
    return value.strip()


def _string_list(
    value: Any, field_name: str, *, allow_empty: bool = False
) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list of strings")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{field_name} must be a list of non-empty strings")
    normalized = sorted({item.strip() for item in value})
    if not allow_empty and not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized


def _epoch(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be an epoch timestamp")
    if not math.isfinite(float(value)) or int(value) != value:
        raise ValueError(f"{field_name} must be an epoch timestamp")
    return int(value)


def _validate_caveat(caveat: Any) -> dict[str, Any]:
    if not isinstance(caveat, dict):
        raise ValueError("capability token caveat must be an object")
    caveat_type = caveat.get("type")
    if caveat_type not in VALID_CAVEAT_TYPES:
        raise ValueError(f"unknown caveat type: {caveat_type}")
    if caveat_type == CAVEAT_TIME:
        _epoch(caveat.get("not_after"), "time caveat not_after")
    elif caveat_type == CAVEAT_IP:
        _string_list(caveat.get("allowed_ips"), "IP caveat allowed_ips")
    elif caveat_type == CAVEAT_RESOURCE:
        _string_list(caveat.get("resources"), "resource caveat resources")
    elif caveat_type == CAVEAT_SCOPE:
        _string_list(caveat.get("scopes"), "scope caveat scopes", allow_empty=True)
    elif caveat_type == CAVEAT_AGENT:
        _string_list(caveat.get("agent_ids"), "agent caveat agent_ids")
    return caveat


def _validated_caveats(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("capability token caveats must be a list")
    return [_validate_caveat(caveat) for caveat in value]


def _assert_actor_agent(
    actor: ResourceAuthContext, asserted_agent_id: str, token_id: str
) -> None:
    if actor.agent_id is not None and actor.agent_id != asserted_agent_id:
        raise KeyError(f"capability token not found: {token_id}")


@dataclass(frozen=True)
class _ParsedToken:
    token_id: str
    authority: dict[str, Any]
    blocks: list[dict[str, Any]]
    signatures: list[str]
    effective_scopes: list[str]
    caveats: list[dict[str, Any]]


def _parse_and_verify_token(token: Any) -> _ParsedToken:
    if not isinstance(token, dict):
        raise ValueError("invalid capability token format")
    if token.get("version") != _TOKEN_VERSION:
        raise ValueError("unsupported capability token version")
    if set(token) != {"token_id", "version", "authority", "blocks", "signatures"}:
        raise ValueError("invalid capability token format")

    token_id = _required_string(token.get("token_id"), "capability token ID")
    authority = token.get("authority")
    blocks = token.get("blocks")
    signatures = token.get("signatures")
    if not isinstance(authority, dict) or not isinstance(blocks, list):
        raise ValueError("invalid capability token format")
    if not isinstance(signatures, list) or any(
        not isinstance(sig, str) for sig in signatures
    ):
        raise ValueError("invalid capability token signatures")
    if len(blocks) >= _MAX_BLOCKS or len(signatures) != len(blocks) + 1:
        raise ValueError("invalid capability token block chain")

    required_authority_keys = {
        "block_index",
        "issuer",
        "subject",
        "audience",
        "resource",
        "scopes",
        "caveats",
        "facts",
        "issued_at",
        "expires_at",
    }
    if set(authority) != required_authority_keys or authority.get("block_index") != 0:
        raise ValueError("invalid capability token authority block")
    _required_string(authority.get("issuer"), "capability token issuer")
    _required_string(authority.get("subject"), "capability token subject")
    _required_string(authority.get("audience"), "capability token audience")
    _required_string(authority.get("resource"), "capability token resource")
    effective_scopes = _string_list(authority.get("scopes"), "capability token scopes")
    all_caveats = _validated_caveats(authority.get("caveats"))
    if not isinstance(authority.get("facts"), dict):
        raise ValueError("capability token facts must be an object")
    _epoch(authority.get("issued_at"), "capability token issued_at")
    _epoch(authority.get("expires_at"), "capability token expires_at")

    secret = _signing_secret()
    expected_signature = _sign_block(_canonical_json(authority), secret)
    if not hmac.compare_digest(signatures[0], expected_signature):
        raise PermissionError("authority block signature mismatch")

    parent_scopes = set(effective_scopes)
    for index, block in enumerate(blocks, start=1):
        if not isinstance(block, dict) or block.get("block_index") != index:
            raise ValueError("invalid capability token block chain")
        derived_key = _block_key(signatures[index - 1], secret)
        expected_signature = _sign_block(_canonical_json(block), derived_key)
        if not hmac.compare_digest(signatures[index], expected_signature):
            raise PermissionError(f"block {index} signature mismatch")

        if "third_party_verifier" in block:
            required_keys = {
                "block_index",
                "third_party_verifier",
                "verification_data",
                "verified_at",
                "scopes",
                "caveats",
            }
            if set(block) != required_keys:
                raise ValueError("invalid third-party capability token block")
            _required_string(block.get("third_party_verifier"), "third-party verifier")
            if not isinstance(block.get("verification_data"), dict):
                raise ValueError("third-party verification data must be an object")
            _epoch(block.get("verified_at"), "third-party verification timestamp")
            if block.get("scopes") != [] or block.get("caveats") != []:
                raise ValueError("third-party block cannot modify authority")
            continue

        required_keys = {
            "block_index",
            "attenuator",
            "scopes",
            "caveats",
            "attenuated_at",
        }
        if set(block) != required_keys:
            raise ValueError("invalid capability token attenuation block")
        _required_string(block.get("attenuator"), "capability token attenuator")
        block_scopes = _string_list(
            block.get("scopes"),
            "capability token attenuation scopes",
            allow_empty=True,
        )
        if "*" not in parent_scopes and not set(block_scopes).issubset(parent_scopes):
            raise PermissionError("capability token scope escalation denied")
        effective_scopes = block_scopes
        parent_scopes = set(block_scopes)
        all_caveats.extend(_validated_caveats(block.get("caveats")))
        _epoch(block.get("attenuated_at"), "capability token attenuation timestamp")

    return _ParsedToken(
        token_id=token_id,
        authority=authority,
        blocks=blocks,
        signatures=signatures,
        effective_scopes=effective_scopes,
        caveats=all_caveats,
    )


def _root_field(root: dict[str, Any], field_name: str) -> Any:
    if field_name not in root:
        raise PermissionError("persisted capability token authority is incomplete")
    return root[field_name]


def _load_root(parsed: _ParsedToken, actor: ResourceAuthContext) -> dict[str, Any]:
    try:
        root = IDENTITY_STORAGE.get_capability_token_root_for_actor(
            parsed.token_id, actor
        )
    except (KeyError, PermissionError) as exc:
        raise KeyError(f"capability token not found: {parsed.token_id}") from exc
    if not isinstance(root, dict):
        raise KeyError(f"capability token not found: {parsed.token_id}")

    authority = parsed.authority
    comparisons = {
        "token_id": parsed.token_id,
        "issuer_agent_id": authority["issuer"],
        "subject_agent_id": authority["subject"],
        "audience": authority["audience"],
        "resource": authority["resource"],
        "issued_at_epoch": authority["issued_at"],
        "expires_at_epoch": authority["expires_at"],
        "scopes": authority["scopes"],
    }
    for field_name, token_value in comparisons.items():
        root_value = _root_field(root, field_name)
        if field_name == "scopes":
            try:
                root_value = _string_list(
                    root_value, "persisted capability token scopes"
                )
            except ValueError as exc:
                raise PermissionError(
                    "persisted capability token authority is incomplete"
                ) from exc
        if root_value != token_value:
            raise PermissionError("capability token does not match persisted authority")

    if bool(_root_field(root, "revoked")):
        raise PermissionError("capability token is revoked")
    if _root_field(root, "identity_active") is not True:
        raise PermissionError("capability token identity is not active")
    if _root_field(root, "generations_current") is not True:
        raise PermissionError("capability token identity generation is stale")
    if int(_root_field(root, "expires_at_epoch")) <= int(time.time()):
        raise PermissionError("capability token is expired")
    return root


def _load_authoritative_token(token: Any, actor: ResourceAuthContext) -> _ParsedToken:
    parsed = _parse_and_verify_token(token)
    _load_root(parsed, actor)
    return parsed


def issue_capability_token(
    *,
    issuer_agent_id: str,
    subject_agent_id: str,
    scopes: list[str],
    actor: ResourceAuthContext,
    audience: str,
    resource: str,
    caveats: list[dict[str, Any]] | None = None,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    facts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Issue and persist a version 2 capability-token authority root."""
    context = require_resource_actor(actor)
    issuer = _required_string(issuer_agent_id, "issuer_agent_id")
    subject = _required_string(subject_agent_id, "subject_agent_id")
    token_audience = _required_string(audience, "audience")
    token_resource = _required_string(resource, "resource")
    normalized_scopes = _string_list(scopes, "scopes")
    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or ttl_seconds <= 0
    ):
        raise ValueError("ttl_seconds must be a positive integer")
    if facts is not None and not isinstance(facts, dict):
        raise ValueError("facts must be an object")

    now = int(time.time())
    expires_at = now + ttl_seconds
    token_id = f"cap-{uuid.uuid4().hex[:16]}"
    resolved_caveats = [_validate_caveat(caveat) for caveat in list(caveats or [])]
    resolved_caveats.append(make_time_caveat(not_after=expires_at))
    authority: dict[str, Any] = {
        "block_index": 0,
        "issuer": issuer,
        "subject": subject,
        "audience": token_audience,
        "resource": token_resource,
        "scopes": normalized_scopes,
        "caveats": resolved_caveats,
        "facts": facts or {},
        "issued_at": now,
        "expires_at": expires_at,
    }

    signature = _sign_block(_canonical_json(authority), _signing_secret())
    token: dict[str, Any] = {
        "token_id": token_id,
        "version": _TOKEN_VERSION,
        "authority": authority,
        "blocks": [],
        "signatures": [signature],
    }
    IDENTITY_STORAGE.create_capability_token_root_for_actor(
        actor=context,
        token_id=token_id,
        issuer_agent_id=issuer,
        subject_agent_id=subject,
        audience=token_audience,
        resource=token_resource,
        issued_at_epoch=now,
        expires_at_epoch=expires_at,
        scopes=normalized_scopes,
    )
    _log.info(
        "capability token issued: token_id=%s issuer=%s subject=%s",
        token_id,
        issuer,
        subject,
    )
    return token


def attenuate_token(
    token: dict[str, Any],
    *,
    actor: ResourceAuthContext,
    scopes: list[str] | None = None,
    caveats: list[dict[str, Any]] | None = None,
    attenuator_agent_id: str,
) -> dict[str, Any]:
    """Append a signed block that can only reduce persisted authority."""
    context = require_resource_actor(actor)
    parsed = _load_authoritative_token(token, context)
    attenuator = _required_string(attenuator_agent_id, "attenuator_agent_id")
    _assert_actor_agent(context, attenuator, parsed.token_id)
    if len(parsed.blocks) >= _MAX_BLOCKS - 1:
        raise ValueError(f"maximum block count ({_MAX_BLOCKS}) reached")

    parent_scopes = set(parsed.effective_scopes)
    new_scopes = (
        parsed.effective_scopes
        if scopes is None
        else _string_list(scopes, "scopes", allow_empty=True)
    )
    if "*" not in parent_scopes:
        excess = set(new_scopes) - parent_scopes
        if excess:
            raise PermissionError(
                f"scope escalation denied: {sorted(excess)} not in parent scopes"
            )
    resolved_caveats = [_validate_caveat(caveat) for caveat in list(caveats or [])]

    new_block: dict[str, Any] = {
        "block_index": len(parsed.blocks) + 1,
        "attenuator": attenuator,
        "scopes": new_scopes,
        "caveats": resolved_caveats,
        "attenuated_at": int(time.time()),
    }
    derived_key = _block_key(parsed.signatures[-1], _signing_secret())
    block_signature = _sign_block(_canonical_json(new_block), derived_key)
    result = {
        "token_id": parsed.token_id,
        "version": _TOKEN_VERSION,
        "authority": parsed.authority,
        "blocks": parsed.blocks + [new_block],
        "signatures": parsed.signatures + [block_signature],
    }
    _log.info(
        "capability token attenuated: token_id=%s block=%d by=%s",
        parsed.token_id,
        new_block["block_index"],
        attenuator,
    )
    return result


def _evaluate_caveats(
    parsed: _ParsedToken,
    *,
    source_ip: str | None,
    resource: str,
) -> tuple[list[str] | None, str | None]:
    effective_scopes = set(parsed.effective_scopes)
    now = int(time.time())
    for caveat in parsed.caveats:
        caveat_type = caveat["type"]
        if caveat_type == CAVEAT_TIME:
            if now >= _epoch(caveat["not_after"], "time caveat not_after"):
                return None, "token expired (time caveat)"
        elif caveat_type == CAVEAT_IP:
            if source_ip is None:
                return None, "source IP context is required"
            if source_ip not in caveat["allowed_ips"]:
                return None, "source IP is not permitted"
        elif caveat_type == CAVEAT_RESOURCE:
            if not resource:
                return None, "resource context is required"
            if resource not in caveat["resources"]:
                return None, "resource is not permitted"
        elif caveat_type == CAVEAT_SCOPE:
            effective_scopes.intersection_update(caveat["scopes"])
        elif caveat_type == CAVEAT_AGENT:
            if parsed.authority["subject"] not in caveat["agent_ids"]:
                return None, "subject agent is not permitted"
    return sorted(effective_scopes), None


def verify_capability_token(
    token: dict[str, Any],
    *,
    actor: ResourceAuthContext,
    source_ip: str | None,
    audience: str | None,
    resource: str | None,
    required_scope: str | None = None,
) -> dict[str, Any]:
    """Verify v2 signatures, persisted authority, context, caveats, and scope."""
    context = require_resource_actor(actor)
    try:
        expected_audience = _required_string(audience, "verification audience")
        expected_resource = _required_string(resource, "verification resource")
        if required_scope is not None:
            required_scope = _required_string(required_scope, "required_scope")
        parsed = _parse_and_verify_token(token)
        _load_root(parsed, context)
        if parsed.authority["audience"] != expected_audience:
            return {"valid": False, "reason": "capability token audience mismatch"}
        if parsed.authority["resource"] != expected_resource:
            return {"valid": False, "reason": "capability token resource mismatch"}
        effective_scopes, caveat_failure = _evaluate_caveats(
            parsed,
            source_ip=source_ip,
            resource=expected_resource,
        )
        if caveat_failure is not None or effective_scopes is None:
            return {
                "valid": False,
                "reason": caveat_failure or "capability token caveat denied",
            }
        if (
            required_scope
            and required_scope not in effective_scopes
            and "*" not in effective_scopes
        ):
            return {
                "valid": False,
                "reason": f"missing required scope: {required_scope}",
            }
    except KeyError:
        return {"valid": False, "reason": "capability token not found"}
    except (TypeError, ValueError, PermissionError) as exc:
        return {"valid": False, "reason": str(exc) or "invalid capability token"}

    return {
        "valid": True,
        "token_id": parsed.token_id,
        "issuer": parsed.authority["issuer"],
        "subject": parsed.authority["subject"],
        "audience": parsed.authority["audience"],
        "resource": parsed.authority["resource"],
        "effective_scopes": effective_scopes,
        "block_count": len(parsed.blocks) + 1,
        "caveat_count": len(parsed.caveats),
    }


def add_third_party_block(
    token: dict[str, Any],
    *,
    actor: ResourceAuthContext,
    verifier_id: str,
    verification_data: dict[str, Any],
) -> dict[str, Any]:
    """Append a signed external-attestation block without changing authority."""
    context = require_resource_actor(actor)
    parsed = _load_authoritative_token(token, context)
    verifier = _required_string(verifier_id, "verifier_id")
    _assert_actor_agent(context, verifier, parsed.token_id)
    if not isinstance(verification_data, dict):
        raise ValueError("verification_data must be an object")
    if len(parsed.blocks) >= _MAX_BLOCKS - 1:
        raise ValueError(f"maximum block count ({_MAX_BLOCKS}) reached")

    block: dict[str, Any] = {
        "block_index": len(parsed.blocks) + 1,
        "third_party_verifier": verifier,
        "verification_data": verification_data,
        "verified_at": int(time.time()),
        "scopes": [],
        "caveats": [],
    }
    derived_key = _block_key(parsed.signatures[-1], _signing_secret())
    block_signature = _sign_block(_canonical_json(block), derived_key)
    result = {
        "token_id": parsed.token_id,
        "version": _TOKEN_VERSION,
        "authority": parsed.authority,
        "blocks": parsed.blocks + [block],
        "signatures": parsed.signatures + [block_signature],
    }
    _log.info(
        "third-party block added: token_id=%s verifier=%s", parsed.token_id, verifier
    )
    return result


@serialized_authority_mutation
def revoke_capability_token(
    token_id: str,
    *,
    actor: ResourceAuthContext,
    reason: str,
) -> dict[str, Any]:
    """Revoke a persisted capability-token root within the actor boundary."""
    context = require_resource_actor(actor)
    resolved_token_id = _required_string(token_id, "token_id")
    resolved_reason = _required_string(reason, "reason")
    result = IDENTITY_STORAGE.revoke_capability_token_root_for_actor(
        resolved_token_id,
        context,
        resolved_reason,
    )
    if not isinstance(result, dict):
        raise RuntimeError(
            "capability token revocation persistence returned an invalid result"
        )
    return result


def get_capability_token(
    token_id: str,
    *,
    actor: ResourceAuthContext,
) -> dict[str, Any]:
    """Return actor-visible persisted authority metadata, never bearer material."""
    context = require_resource_actor(actor)
    resolved_token_id = _required_string(token_id, "token_id")
    result = IDENTITY_STORAGE.get_capability_token_root_for_actor(
        resolved_token_id, context
    )
    if not isinstance(result, dict):
        raise RuntimeError("capability token persistence returned an invalid result")
    return result


def list_capability_tokens(
    *,
    actor: ResourceAuthContext,
    active_only: bool = True,
) -> list[dict[str, Any]]:
    """List persisted roots visible to the actor, never bearer token material."""
    context = require_resource_actor(actor)
    if not isinstance(active_only, bool):
        raise ValueError("active_only must be a boolean")
    roots = IDENTITY_STORAGE.list_capability_token_roots_for_actor(context, active_only)
    if not isinstance(roots, list) or any(not isinstance(root, dict) for root in roots):
        raise RuntimeError("capability token persistence returned an invalid result")
    return roots
