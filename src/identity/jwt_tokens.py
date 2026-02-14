"""JWT token issue/verify for AAP-compliant agent tokens.

Uses PyJWT for standards-compliant JWT handling. Supports HS256 (HMAC)
for symmetric signing using the identity signing secret, with RS256/ES256
stubs for future asymmetric key support.
"""
from __future__ import annotations

import os
import uuid
from typing import Any

import jwt

from src.common.time import utc_now_epoch
from src.identity.jwt_constants import (
    ALG_HS256,
    CLAIM_AGENT_CAPABILITIES,
    CLAIM_AGENT_ID,
    CLAIM_AUD,
    CLAIM_BEHAVIORAL_ATTESTATION,
    CLAIM_DELEGATION_CHAIN,
    CLAIM_DELEGATION_CHAIN_ID,
    CLAIM_EXP,
    CLAIM_IAT,
    CLAIM_ISS,
    CLAIM_JTI,
    CLAIM_OVERSIGHT_LEVEL,
    CLAIM_PEER_ATTESTATIONS,
    CLAIM_RUNTIME_CONSTRAINTS,
    CLAIM_SCOPE,
    CLAIM_SUB,
    CLAIM_TASK_BINDING,
    DEFAULT_ALGORITHM,
    DEFAULT_ISSUER,
    DEFAULT_JWT_TTL_SECONDS,
    MAX_JWT_TTL_SECONDS,
    MIN_JWT_TTL_SECONDS,
    VALID_OVERSIGHT_LEVELS,
)


def _jwt_signing_secret() -> str:
    secret = os.getenv("AGENTHUB_IDENTITY_SIGNING_SECRET")
    if not secret or not secret.strip():
        raise RuntimeError("AGENTHUB_IDENTITY_SIGNING_SECRET is required for JWT operations")
    return secret.strip()


def issue_jwt(
    *,
    subject: str,
    agent_id: str,
    scopes: list[str] | None = None,
    audience: str | None = None,
    ttl_seconds: int = DEFAULT_JWT_TTL_SECONDS,
    agent_capabilities: list[str] | None = None,
    task_binding: str | None = None,
    oversight_level: str | None = None,
    delegation_chain_id: str | None = None,
    delegation_chain: list[dict[str, Any]] | None = None,
    behavioral_attestation: dict[str, Any] | None = None,
    runtime_constraints: dict[str, Any] | None = None,
    peer_attestations: list[dict[str, Any]] | None = None,
    issuer: str = DEFAULT_ISSUER,
    algorithm: str = DEFAULT_ALGORITHM,
    extra_claims: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Issue a JWT with AAP-compliant claims.

    Returns a dict with the encoded token and metadata.
    """
    ttl = max(MIN_JWT_TTL_SECONDS, min(int(ttl_seconds), MAX_JWT_TTL_SECONDS))
    now = utc_now_epoch()
    jti = str(uuid.uuid4())

    payload: dict[str, Any] = {
        CLAIM_ISS: issuer,
        CLAIM_SUB: subject,
        CLAIM_IAT: now,
        CLAIM_EXP: now + ttl,
        CLAIM_JTI: jti,
        CLAIM_AGENT_ID: agent_id,
    }

    if scopes:
        payload[CLAIM_SCOPE] = " ".join(sorted(scopes))
    if audience:
        payload[CLAIM_AUD] = audience
    if agent_capabilities:
        payload[CLAIM_AGENT_CAPABILITIES] = sorted(agent_capabilities)
    if task_binding:
        payload[CLAIM_TASK_BINDING] = task_binding
    if oversight_level:
        if oversight_level not in VALID_OVERSIGHT_LEVELS:
            raise ValueError(f"invalid oversight_level: {oversight_level}, must be one of {sorted(VALID_OVERSIGHT_LEVELS)}")
        payload[CLAIM_OVERSIGHT_LEVEL] = oversight_level
    if delegation_chain_id:
        payload[CLAIM_DELEGATION_CHAIN_ID] = delegation_chain_id
    if delegation_chain:
        payload[CLAIM_DELEGATION_CHAIN] = delegation_chain
    if behavioral_attestation:
        payload[CLAIM_BEHAVIORAL_ATTESTATION] = behavioral_attestation
    if runtime_constraints:
        payload[CLAIM_RUNTIME_CONSTRAINTS] = runtime_constraints
    if peer_attestations:
        payload[CLAIM_PEER_ATTESTATIONS] = peer_attestations

    if extra_claims:
        for key, value in extra_claims.items():
            if key not in payload:
                payload[key] = value

    secret = _jwt_signing_secret()
    token = jwt.encode(payload, secret, algorithm=algorithm)

    return {
        "token": token,
        "token_type": "Bearer",
        "jti": jti,
        "subject": subject,
        "agent_id": agent_id,
        "issuer": issuer,
        "issued_at": now,
        "expires_at": now + ttl,
        "algorithm": algorithm,
        "scopes": sorted(scopes) if scopes else [],
    }


def verify_jwt(
    token: str,
    *,
    audience: str | None = None,
    issuer: str = DEFAULT_ISSUER,
    algorithms: list[str] | None = None,
    require_agent_id: bool = True,
) -> dict[str, Any]:
    """Verify and decode a JWT token.

    Returns the decoded claims dict. Raises ValueError on invalid tokens.
    """
    secret = _jwt_signing_secret()
    algs = algorithms or [ALG_HS256]

    options: dict[str, Any] = {}
    kwargs: dict[str, Any] = {"algorithms": algs}
    if audience:
        kwargs["audience"] = audience
    else:
        options["verify_aud"] = False
    if issuer:
        kwargs["issuer"] = issuer
    kwargs["options"] = options

    try:
        claims = jwt.decode(token, secret, **kwargs)
    except jwt.ExpiredSignatureError as exc:
        raise ValueError("JWT token expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise ValueError("JWT audience mismatch") from exc
    except jwt.InvalidIssuerError as exc:
        raise ValueError("JWT issuer mismatch") from exc
    except jwt.InvalidSignatureError as exc:
        raise ValueError("JWT signature invalid") from exc
    except jwt.DecodeError as exc:
        raise ValueError(f"JWT decode failed: {exc}") from exc
    except jwt.PyJWTError as exc:
        raise ValueError(f"JWT validation failed: {exc}") from exc

    if require_agent_id and CLAIM_AGENT_ID not in claims:
        raise ValueError("JWT missing required agent_id claim")

    # Normalize scope claim to list
    raw_scope = claims.get(CLAIM_SCOPE)
    if isinstance(raw_scope, str):
        claims["scopes"] = raw_scope.split()
    else:
        claims["scopes"] = []

    return claims


def decode_jwt_unverified(token: str) -> dict[str, Any]:
    """Decode a JWT without signature verification. For inspection only."""
    try:
        claims = jwt.decode(token, options={"verify_signature": False}, algorithms=[ALG_HS256])
    except jwt.DecodeError as exc:
        raise ValueError(f"JWT decode failed: {exc}") from exc
    return claims


def get_jwks() -> dict[str, Any]:
    """Return a JWKS (JSON Web Key Set) for the symmetric signing key.

    For HS256, we return a minimal JWKS with key type 'oct' (octet sequence).
    In production, RS256/ES256 would expose the public key here.
    """
    return {
        "keys": [
            {
                "kty": "oct",
                "alg": ALG_HS256,
                "use": "sig",
                "kid": "agenthub-default-hs256",
            }
        ],
    }
