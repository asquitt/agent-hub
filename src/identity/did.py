"""Decentralized Identifiers (DIDs) and Verifiable Credentials (VCs).

Implements W3C DID Core 1.0 with a custom `did:agenthub:` method and
W3C Verifiable Credentials Data Model 2.0 with JWT proof format.

- DID Document generation with verification methods
- DID resolution and deactivation
- Verifiable Credential issuance as JWT
- VC verification and revocation checking
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

_log = logging.getLogger("agenthub.did")

# DID method
DID_METHOD = "agenthub"
DID_PREFIX = f"did:{DID_METHOD}:"

# VC types
VC_TYPE_AGENT_IDENTITY = "AgentIdentityCredential"
VC_TYPE_CAPABILITY_GRANT = "CapabilityGrantCredential"
VC_TYPE_TRUST_ATTESTATION = "TrustAttestationCredential"
VALID_VC_TYPES = {VC_TYPE_AGENT_IDENTITY, VC_TYPE_CAPABILITY_GRANT, VC_TYPE_TRUST_ATTESTATION}

# In-memory stores
_did_documents: dict[str, dict[str, Any]] = {}  # did -> document
_verifiable_credentials: dict[str, dict[str, Any]] = {}  # vc_id -> credential
_revoked_vcs: set[str] = set()  # set of revoked vc_ids


def _signing_secret() -> bytes:
    secret = os.getenv("AGENTHUB_IDENTITY_SIGNING_SECRET", "")
    return secret.encode("utf-8") if secret else b"default-test-key"


def _domain() -> str:
    return os.getenv("AGENTHUB_SPIFFE_TRUST_DOMAIN", "agenthub.local")


def _sign(data: str) -> str:
    """HMAC-SHA256 signature over canonical data."""
    return hmac.new(_signing_secret(), data.encode("utf-8"), hashlib.sha256).hexdigest()


def _canonical(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


# ── DID Operations ────────────────────────────────────────────────


def create_did(
    *,
    agent_id: str,
    controller: str | None = None,
    service_endpoints: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Create a DID Document for an agent.

    Format: did:agenthub:<domain>:<agent_id_hash>
    """
    domain = _domain()
    id_hash = hashlib.sha256(agent_id.encode("utf-8")).hexdigest()[:16]
    did = f"{DID_PREFIX}{domain}:{id_hash}"

    if did in _did_documents:
        existing = _did_documents[did]
        if existing.get("deactivated"):
            pass  # Allow re-creation of deactivated DIDs
        else:
            return existing

    now = time.time()
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    # Verification method
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

    # Build services
    services: list[dict[str, str]] = []
    if service_endpoints:
        for i, ep in enumerate(service_endpoints):
            services.append({
                "id": f"{did}#service-{i}",
                "type": ep.get("type", "AgentService"),
                "serviceEndpoint": ep.get("endpoint", ""),
            })

    doc: dict[str, Any] = {
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
        "agent_id": agent_id,
    }

    # Integrity proof
    doc["proof"] = {
        "type": "DataIntegrityProof",
        "cryptosuite": "hmac-sha256",
        "verificationMethod": vm_id,
        "created": now_iso,
        "proofValue": _sign(_canonical({k: v for k, v in doc.items() if k != "proof"})),
    }

    _did_documents[did] = doc
    _log.info("DID created: %s for agent %s", did, agent_id)
    return doc


def resolve_did(did: str) -> dict[str, Any]:
    """Resolve a DID to its DID Document."""
    if not did.startswith(DID_PREFIX):
        raise ValueError(f"unsupported DID method: {did}")

    doc = _did_documents.get(did)
    if doc is None:
        raise KeyError(f"DID not found: {did}")

    return {
        "didDocument": doc,
        "didResolutionMetadata": {
            "contentType": "application/did+json",
            "resolved": True,
            "deactivated": doc.get("deactivated", False),
        },
        "didDocumentMetadata": {
            "created": doc.get("created"),
            "updated": doc.get("updated"),
        },
    }


def deactivate_did(did: str, *, reason: str = "manual") -> dict[str, Any]:
    """Deactivate a DID (soft delete)."""
    doc = _did_documents.get(did)
    if doc is None:
        raise KeyError(f"DID not found: {did}")

    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()))
    doc["deactivated"] = True
    doc["updated"] = now_iso
    doc["deactivation_reason"] = reason

    _log.info("DID deactivated: %s reason=%s", did, reason)
    return doc


def list_dids(*, active_only: bool = True) -> list[dict[str, Any]]:
    """List all DID documents."""
    results = []
    for doc in _did_documents.values():
        if active_only and doc.get("deactivated"):
            continue
        results.append({
            "id": doc["id"],
            "agent_id": doc.get("agent_id"),
            "created": doc.get("created"),
            "deactivated": doc.get("deactivated", False),
        })
    return results


# ── Verifiable Credentials ────────────────────────────────────────


def issue_verifiable_credential(
    *,
    issuer_did: str,
    subject_did: str,
    credential_type: str = VC_TYPE_AGENT_IDENTITY,
    claims: dict[str, Any] | None = None,
    ttl_seconds: int = 86400,
) -> dict[str, Any]:
    """Issue a Verifiable Credential as a JWT-secured VC."""
    if credential_type not in VALID_VC_TYPES:
        raise ValueError(f"invalid VC type: {credential_type}")

    # Verify issuer DID exists and is active
    issuer_doc = _did_documents.get(issuer_did)
    if issuer_doc is None:
        raise KeyError(f"issuer DID not found: {issuer_did}")
    if issuer_doc.get("deactivated"):
        raise ValueError(f"issuer DID is deactivated: {issuer_did}")

    vc_id = f"urn:uuid:{uuid.uuid4()}"
    now = time.time()
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    exp_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + ttl_seconds))

    credential_subject: dict[str, Any] = {
        "id": subject_did,
    }
    if claims:
        credential_subject.update(claims)

    vc: dict[str, Any] = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1",
        ],
        "id": vc_id,
        "type": ["VerifiableCredential", credential_type],
        "issuer": issuer_did,
        "issuanceDate": now_iso,
        "expirationDate": exp_iso,
        "credentialSubject": credential_subject,
    }

    # JWT proof: sign the VC payload
    jwt_payload = {
        "iss": issuer_did,
        "sub": subject_did,
        "vc": vc,
        "iat": int(now),
        "exp": int(now + ttl_seconds),
        "jti": vc_id,
    }
    jwt_canonical = _canonical(jwt_payload)
    signature = _sign(jwt_canonical)

    record: dict[str, Any] = {
        "vc_id": vc_id,
        "credential": vc,
        "jwt_proof": {
            "algorithm": "HS256",
            "signature": signature,
        },
        "issuer_did": issuer_did,
        "subject_did": subject_did,
        "credential_type": credential_type,
        "issued_at": now,
        "expires_at": now + ttl_seconds,
        "revoked": False,
    }

    _verifiable_credentials[vc_id] = record
    _log.info("VC issued: id=%s type=%s issuer=%s subject=%s", vc_id, credential_type, issuer_did, subject_did)
    return record


def verify_verifiable_credential(vc_id: str) -> dict[str, Any]:
    """Verify a Verifiable Credential's integrity, expiry, and revocation status."""
    record = _verifiable_credentials.get(vc_id)
    if record is None:
        raise KeyError(f"VC not found: {vc_id}")

    now = time.time()
    expired = now > record["expires_at"]
    revoked = vc_id in _revoked_vcs

    # Re-compute signature
    jwt_payload = {
        "iss": record["issuer_did"],
        "sub": record["subject_did"],
        "vc": record["credential"],
        "iat": int(record["issued_at"]),
        "exp": int(record["expires_at"]),
        "jti": vc_id,
    }
    expected_sig = _sign(_canonical(jwt_payload))
    stored_sig = record.get("jwt_proof", {}).get("signature", "")
    signature_valid = hmac.compare_digest(expected_sig, stored_sig)

    # Check issuer DID status
    issuer_doc = _did_documents.get(record["issuer_did"])
    issuer_active = issuer_doc is not None and not issuer_doc.get("deactivated", False)

    valid = signature_valid and not expired and not revoked and issuer_active
    reasons: list[str] = []
    if not signature_valid:
        reasons.append("invalid signature")
    if expired:
        reasons.append("expired")
    if revoked:
        reasons.append("revoked")
    if not issuer_active:
        reasons.append("issuer DID deactivated")

    return {
        "vc_id": vc_id,
        "valid": valid,
        "signature_valid": signature_valid,
        "expired": expired,
        "revoked": revoked,
        "issuer_active": issuer_active,
        "reasons": reasons,
        "credential_type": record["credential_type"],
        "issuer_did": record["issuer_did"],
        "subject_did": record["subject_did"],
    }


def revoke_verifiable_credential(vc_id: str, *, reason: str = "manual") -> dict[str, Any]:
    """Revoke a Verifiable Credential."""
    record = _verifiable_credentials.get(vc_id)
    if record is None:
        raise KeyError(f"VC not found: {vc_id}")

    _revoked_vcs.add(vc_id)
    record["revoked"] = True
    record["revoked_at"] = time.time()
    record["revoke_reason"] = reason

    _log.info("VC revoked: id=%s reason=%s", vc_id, reason)
    return {
        "vc_id": vc_id,
        "revoked": True,
        "reason": reason,
    }


def list_verifiable_credentials(
    *,
    issuer_did: str | None = None,
    subject_did: str | None = None,
    credential_type: str | None = None,
    active_only: bool = True,
) -> list[dict[str, Any]]:
    """List verifiable credentials with optional filters."""
    now = time.time()
    results: list[dict[str, Any]] = []
    for record in _verifiable_credentials.values():
        if issuer_did and record["issuer_did"] != issuer_did:
            continue
        if subject_did and record["subject_did"] != subject_did:
            continue
        if credential_type and record["credential_type"] != credential_type:
            continue
        if active_only:
            if record["vc_id"] in _revoked_vcs:
                continue
            if now > record["expires_at"]:
                continue
        results.append({
            "vc_id": record["vc_id"],
            "credential_type": record["credential_type"],
            "issuer_did": record["issuer_did"],
            "subject_did": record["subject_did"],
            "issued_at": record["issued_at"],
            "expires_at": record["expires_at"],
            "revoked": record["vc_id"] in _revoked_vcs,
        })
    return results


def reset_for_tests() -> None:
    """Clear all DID/VC data for testing."""
    _did_documents.clear()
    _verifiable_credentials.clear()
    _revoked_vcs.clear()
