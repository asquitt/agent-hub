"""Tenant-scoped AgentHub DID documents and verifiable credential records.

The module provides an AgentHub-specific DID method and JWT-style HMAC proof
records. Durable authority, ownership, revocation, and identity-generation
snapshots are owned by the identity storage layer.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from typing import Any, cast

from src.identity.constants import STATUS_ACTIVE
from src.identity.storage import (
    IDENTITY_STORAGE,
    ResourceAuthContext,
    require_resource_actor,
)

_log = logging.getLogger("agenthub.did")

# DID method
DID_METHOD = "agenthub"
DID_PREFIX = f"did:{DID_METHOD}:"

# VC types
VC_TYPE_AGENT_IDENTITY = "AgentIdentityCredential"
VC_TYPE_CAPABILITY_GRANT = "CapabilityGrantCredential"
VC_TYPE_TRUST_ATTESTATION = "TrustAttestationCredential"
VALID_VC_TYPES = {
    VC_TYPE_AGENT_IDENTITY,
    VC_TYPE_CAPABILITY_GRANT,
    VC_TYPE_TRUST_ATTESTATION,
}


def _signing_secret() -> bytes:
    secret = os.getenv("AGENTHUB_IDENTITY_SIGNING_SECRET", "")
    if not secret:
        raise PermissionError("AGENTHUB_IDENTITY_SIGNING_SECRET is required")
    return secret.encode("utf-8")


def _domain() -> str:
    return os.getenv("AGENTHUB_SPIFFE_TRUST_DOMAIN", "agenthub.local")


def _sign(data: str, *, domain: bytes) -> str:
    """Return a domain-separated HMAC-SHA256 signature over canonical data."""
    key = hmac.new(_signing_secret(), domain, hashlib.sha256).digest()
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()


def _canonical(obj: dict[str, Any]) -> str:
    try:
        return json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("DID/VC payload must be JSON serializable") from exc


def _now_iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _require_active_identity(
    agent_id: str,
    *,
    actor: ResourceAuthContext,
    peer: bool,
) -> dict[str, Any]:
    getter = (
        IDENTITY_STORAGE.get_peer_identity_for_actor
        if peer
        else IDENTITY_STORAGE.get_identity_for_actor
    )
    identity = getter(agent_id, actor)
    if identity["status"] != STATUS_ACTIVE:
        raise PermissionError(f"agent identity is {identity['status']}: {agent_id}")
    return dict(identity)


def _require_active_did(
    did: str,
    *,
    actor: ResourceAuthContext,
    role: str,
    peer: bool = False,
) -> dict[str, Any]:
    getter = (
        IDENTITY_STORAGE.resolve_peer_did_for_actor
        if peer
        else IDENTITY_STORAGE.resolve_did_for_actor
    )
    document = getter(did, actor)
    if document.get("deactivated") is not False:
        raise ValueError(f"{role} DID is deactivated: {did}")
    agent_id = document.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id:
        raise ValueError(f"{role} DID has no bound agent identity: {did}")
    return document


def _did_is_active(
    did: str,
    *,
    actor: ResourceAuthContext,
    peer: bool = False,
) -> tuple[bool, dict[str, Any] | None]:
    try:
        getter = (
            IDENTITY_STORAGE.resolve_peer_did_for_actor
            if peer
            else IDENTITY_STORAGE.resolve_did_for_actor
        )
        document = getter(did, actor)
    except KeyError:
        return False, None
    return document.get("deactivated") is False, document


# DID operations


def create_did(
    *,
    agent_id: str,
    controller: str | None = None,
    service_endpoints: list[dict[str, str]] | None = None,
    actor: ResourceAuthContext,
) -> dict[str, Any]:
    """Create or return the active DID document bound to an agent identity."""
    context = require_resource_actor(actor)
    normalized_agent_id = agent_id.strip()
    if not normalized_agent_id:
        raise ValueError("agent_id is required")
    if context.agent_id is not None and context.agent_id != normalized_agent_id:
        raise PermissionError("agent-bound principal cannot create another agent DID")
    _require_active_identity(normalized_agent_id, actor=context, peer=False)

    domain = _domain()
    id_hash = hashlib.sha256(normalized_agent_id.encode("utf-8")).hexdigest()[:16]
    did = f"{DID_PREFIX}{domain}:{id_hash}"
    if controller is not None and controller != did:
        raise PermissionError(
            "external DID controllers require a verified control transfer"
        )

    try:
        existing = IDENTITY_STORAGE.resolve_did_for_actor(did, context)
    except KeyError:
        existing = None
    if existing is not None:
        if existing.get("deactivated") is not False:
            raise ValueError(f"DID is permanently deactivated: {did}")
        return existing

    now = time.time()
    now_iso = _now_iso(now)
    vm_id = f"{did}#key-1"
    verification_method = {
        "id": vm_id,
        "type": "JsonWebKey2020",
        "controller": controller or did,
        "publicKeyJwk": {
            "kty": "oct",
            "alg": "HS256",
            "kid": f"{id_hash}-key-1",
        },
    }

    services: list[dict[str, str]] = []
    if service_endpoints:
        for index, endpoint in enumerate(service_endpoints):
            services.append(
                {
                    "id": f"{did}#service-{index}",
                    "type": endpoint.get("type", "AgentService"),
                    "serviceEndpoint": endpoint.get("endpoint", ""),
                }
            )

    document: dict[str, Any] = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "controller": controller or did,
        "verificationMethod": [verification_method],
        "authentication": [vm_id],
        "assertionMethod": [vm_id],
        "service": services,
        "created": now_iso,
        "updated": now_iso,
        "deactivated": False,
        "agent_id": normalized_agent_id,
    }
    document["proof"] = {
        "type": "DataIntegrityProof",
        "cryptosuite": "hmac-sha256",
        "verificationMethod": vm_id,
        "created": now_iso,
        "proofValue": _sign(
            _canonical(
                {key: value for key, value in document.items() if key != "proof"}
            ),
            domain=b"agenthub-did-document-v1",
        ),
    }

    stored = IDENTITY_STORAGE.create_did_for_actor(
        actor=context,
        agent_id=normalized_agent_id,
        did=did,
        document=document,
    )
    _log.info("DID created: %s for agent %s", did, normalized_agent_id)
    return stored


def resolve_did(did: str, *, actor: ResourceAuthContext) -> dict[str, Any]:
    """Resolve an actor-visible DID to its document and resolution metadata."""
    context = require_resource_actor(actor)
    if not did.startswith(DID_PREFIX):
        raise ValueError(f"unsupported DID method: {did}")

    document = IDENTITY_STORAGE.resolve_did_for_actor(did, context)
    return {
        "didDocument": document,
        "didResolutionMetadata": {
            "contentType": "application/did+json",
            "resolved": True,
            "deactivated": document.get("deactivated", False),
        },
        "didDocumentMetadata": {
            "created": document.get("created"),
            "updated": document.get("updated"),
        },
    }


def deactivate_did(
    did: str,
    *,
    reason: str = "manual",
    actor: ResourceAuthContext,
) -> dict[str, Any]:
    """Permanently deactivate an actor-visible DID."""
    context = require_resource_actor(actor)
    if not did.startswith(DID_PREFIX):
        raise ValueError(f"unsupported DID method: {did}")
    result = IDENTITY_STORAGE.deactivate_did_for_actor(did, context, reason)
    _log.info("DID deactivated: %s reason=%s", did, reason)
    return result


def list_dids(
    *,
    active_only: bool = True,
    actor: ResourceAuthContext,
) -> list[dict[str, Any]]:
    """List DID summaries visible to an actor."""
    context = require_resource_actor(actor)
    return IDENTITY_STORAGE.list_dids_for_actor(context, active_only)


# Verifiable credentials


def issue_verifiable_credential(
    *,
    issuer_did: str,
    subject_did: str,
    credential_type: str = VC_TYPE_AGENT_IDENTITY,
    claims: dict[str, Any] | None = None,
    ttl_seconds: int = 86400,
    actor: ResourceAuthContext,
) -> dict[str, Any]:
    """Issue a durable, tenant-scoped credential with a JWT-style proof."""
    context = require_resource_actor(actor)
    if credential_type not in VALID_VC_TYPES:
        raise ValueError(f"invalid VC type: {credential_type}")
    if isinstance(ttl_seconds, bool) or ttl_seconds < 60 or ttl_seconds > 2_592_000:
        raise ValueError("ttl_seconds must be between 60 and 2592000")
    if claims is not None and not isinstance(claims, dict):
        raise ValueError("claims must be an object")
    if claims is not None and "id" in claims:
        raise ValueError("credentialSubject.id is reserved")

    if context.agent_id is not None:
        caller_hash = hashlib.sha256(context.agent_id.encode("utf-8")).hexdigest()[:16]
        caller_did = f"{DID_PREFIX}{_domain()}:{caller_hash}"
        if issuer_did != caller_did:
            raise PermissionError("agent-bound principal cannot issue from another DID")

    issuer_document = _require_active_did(
        issuer_did,
        actor=context,
        role="issuer",
    )
    subject_document = _require_active_did(
        subject_did,
        actor=context,
        role="subject",
        peer=True,
    )
    issuer_agent_id = str(issuer_document["agent_id"])
    subject_agent_id = str(subject_document["agent_id"])
    _require_active_identity(issuer_agent_id, actor=context, peer=False)
    _require_active_identity(subject_agent_id, actor=context, peer=True)

    vc_id = f"urn:uuid:{uuid.uuid4()}"
    now = time.time()
    expires_at = now + ttl_seconds
    credential_subject: dict[str, Any] = {"id": subject_did}
    if claims:
        credential_subject.update(claims)

    credential: dict[str, Any] = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1",
        ],
        "id": vc_id,
        "type": ["VerifiableCredential", credential_type],
        "issuer": issuer_did,
        "issuanceDate": _now_iso(now),
        "expirationDate": _now_iso(expires_at),
        "credentialSubject": credential_subject,
    }
    jwt_payload = {
        "iss": issuer_did,
        "sub": subject_did,
        "vc": credential,
        "iat": int(now),
        "exp": int(expires_at),
        "jti": vc_id,
    }
    signature = _sign(_canonical(jwt_payload), domain=b"agenthub-vc-record-v1")
    record: dict[str, Any] = {
        "vc_id": vc_id,
        "credential": credential,
        "jwt_proof": {
            "algorithm": "HS256",
            "signature": signature,
        },
        "issuer_did": issuer_did,
        "subject_did": subject_did,
        "issuer_agent_id": issuer_agent_id,
        "subject_agent_id": subject_agent_id,
        "credential_type": credential_type,
        "issued_at": now,
        "expires_at": expires_at,
        "revoked": False,
    }

    stored = IDENTITY_STORAGE.create_verifiable_credential_for_actor(
        actor=context,
        record=record,
    )
    _log.info(
        "VC issued: id=%s type=%s issuer=%s subject=%s",
        vc_id,
        credential_type,
        issuer_did,
        subject_did,
    )
    return stored


def verify_verifiable_credential(
    vc_id: str,
    *,
    actor: ResourceAuthContext,
) -> dict[str, Any]:
    """Verify proof, expiry, revocation, DID state, and identity generations."""
    context = require_resource_actor(actor)
    record = cast(
        dict[str, Any],
        IDENTITY_STORAGE.get_verifiable_credential_for_actor(vc_id, context),
    )

    credential = record.get("credential")
    proof = record.get("jwt_proof")
    issuer_did = record.get("issuer_did")
    subject_did = record.get("subject_did")
    issued_at = record.get("issued_at")
    expires_at = record.get("expires_at")
    credential_type = record.get("credential_type")

    shape_valid = (
        isinstance(credential, dict)
        and isinstance(proof, dict)
        and isinstance(issuer_did, str)
        and isinstance(subject_did, str)
        and isinstance(issued_at, (int, float))
        and not isinstance(issued_at, bool)
        and isinstance(expires_at, (int, float))
        and not isinstance(expires_at, bool)
        and isinstance(credential_type, str)
    )
    credential_subject = (
        credential.get("credentialSubject") if isinstance(credential, dict) else None
    )
    binding_valid = bool(
        isinstance(credential, dict)
        and credential.get("id") == vc_id
        and credential.get("issuer") == issuer_did
        and isinstance(credential_subject, dict)
        and credential_subject.get("id") == subject_did
    )

    signature_valid = False
    if shape_valid:
        credential_dict = cast(dict[str, Any], credential)
        proof_dict = cast(dict[str, Any], proof)
        issued_at_epoch = cast(int | float, issued_at)
        expires_at_epoch = cast(int | float, expires_at)
        jwt_payload = {
            "iss": issuer_did,
            "sub": subject_did,
            "vc": credential_dict,
            "iat": int(issued_at_epoch),
            "exp": int(expires_at_epoch),
            "jti": vc_id,
        }
        expected_signature = _sign(
            _canonical(jwt_payload),
            domain=b"agenthub-vc-record-v1",
        )
        stored_signature = proof_dict.get("signature")
        signature_valid = isinstance(stored_signature, str) and hmac.compare_digest(
            expected_signature,
            stored_signature,
        )

    now = time.time()
    expired = (
        not isinstance(expires_at, (int, float))
        or isinstance(expires_at, bool)
        or now > expires_at
    )
    revocation_known = isinstance(record.get("revoked"), bool)
    revoked = record.get("revoked") is True

    issuer_active = False
    subject_active = False
    did_identity_binding_valid = False
    if isinstance(issuer_did, str) and isinstance(subject_did, str):
        issuer_did_active, issuer_document = _did_is_active(
            issuer_did,
            actor=context,
            peer=True,
        )
        subject_did_active, subject_document = _did_is_active(
            subject_did,
            actor=context,
            peer=True,
        )
        issuer_active = issuer_did_active and record.get("issuer_active") is True
        subject_active = subject_did_active and record.get("subject_active") is True
        did_identity_binding_valid = bool(
            issuer_document is not None
            and subject_document is not None
            and issuer_document.get("agent_id") == record.get("issuer_agent_id")
            and subject_document.get("agent_id") == record.get("subject_agent_id")
        )

    issuer_generation_current = record.get("issuer_identity_generation_current") is True
    subject_generation_current = (
        record.get("subject_identity_generation_current") is True
    )
    valid = all(
        (
            shape_valid,
            binding_valid,
            did_identity_binding_valid,
            signature_valid,
            not expired,
            revocation_known,
            not revoked,
            issuer_active,
            subject_active,
            issuer_generation_current,
            subject_generation_current,
        )
    )

    reasons: list[str] = []
    if not shape_valid:
        reasons.append("malformed credential record")
    if not binding_valid or not did_identity_binding_valid:
        reasons.append("credential binding mismatch")
    if not signature_valid:
        reasons.append("invalid signature")
    if expired:
        reasons.append("expired")
    if not revocation_known:
        reasons.append("revocation status unavailable")
    elif revoked:
        reasons.append("revoked")
    if not issuer_active:
        reasons.append("issuer DID deactivated")
    if not subject_active:
        reasons.append("subject DID deactivated")
    if not issuer_generation_current:
        reasons.append("issuer identity generation changed")
    if not subject_generation_current:
        reasons.append("subject identity generation changed")

    return {
        "vc_id": vc_id,
        "valid": valid,
        "signature_valid": signature_valid,
        "expired": expired,
        "revoked": revoked,
        "issuer_active": issuer_active,
        "subject_active": subject_active,
        "issuer_identity_generation_current": issuer_generation_current,
        "subject_identity_generation_current": subject_generation_current,
        "reasons": reasons,
        "credential_type": credential_type,
        "issuer_did": issuer_did,
        "subject_did": subject_did,
    }


def revoke_verifiable_credential(
    vc_id: str,
    *,
    reason: str = "manual",
    actor: ResourceAuthContext,
) -> dict[str, Any]:
    """Durably revoke an actor-visible verifiable credential."""
    context = require_resource_actor(actor)
    result = IDENTITY_STORAGE.revoke_verifiable_credential_for_actor(
        vc_id, context, reason
    )
    _log.info("VC revoked: id=%s reason=%s", vc_id, reason)
    return result


def list_verifiable_credentials(
    *,
    issuer_did: str | None = None,
    subject_did: str | None = None,
    credential_type: str | None = None,
    active_only: bool = True,
    actor: ResourceAuthContext,
) -> list[dict[str, Any]]:
    """List actor-visible verifiable credential summaries."""
    context = require_resource_actor(actor)
    return IDENTITY_STORAGE.list_verifiable_credentials_for_actor(
        context,
        issuer_did=issuer_did,
        subject_did=subject_did,
        credential_type=credential_type,
        active_only=active_only,
    )


def reset_for_tests() -> None:
    """Compatibility no-op; identity storage owns persistent test state."""
