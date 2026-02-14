from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.identity.blended import get_blended_identity, verify_on_behalf_of
from src.identity.spiffe import (
    generate_bundle as generate_spiffe_bundle,
    generate_spiffe_id,
    generate_svid,
    verify_spiffe_id,
)
from src.identity.checksum import compute_config_checksum, verify_config_integrity
from src.common.time import iso_from_epoch
from src.identity.constants import CREDENTIAL_TYPE_API_KEY, VALID_CREDENTIAL_TYPES
from src.identity.credentials import (
    get_credential_metadata,
    issue_credential,
    revoke_credential,
    rotate_credential,
)
from src.identity.delegation_tokens import (
    get_delegation_chain,
    issue_delegation_token,
    revoke_delegation_token,
    verify_delegation_token,
)
from src.identity.federation import (
    create_agent_attestation,
    get_trusted_domain,
    list_trusted_domains,
    register_trusted_domain,
    verify_agent_attestation,
)
from src.identity.revocation import (
    bulk_revoke,
    list_revocation_events,
    revoke_agent,
)
from src.identity.storage import (
    bind_human_principal,
    get_agent_identity,
    list_active_sessions,
    register_agent_identity,
    set_configuration_checksum,
    update_agent_identity_status,
)

router = APIRouter(prefix="/v1/identity", tags=["identity"])


# --- Request Models ---


class RegisterAgentIdentityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=256)
    credential_type: str = Field(default=CREDENTIAL_TYPE_API_KEY, max_length=32)
    public_key_pem: str | None = Field(default=None)
    metadata: dict[str, str] | None = Field(default=None)
    human_principal_id: str | None = Field(default=None, max_length=256)
    configuration_checksum: str | None = Field(default=None, max_length=128)


class BindHumanPrincipalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    human_principal_id: str | None = Field(default=None, max_length=256)


class SetConfigurationChecksumRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    checksum: str = Field(min_length=1, max_length=128)


class VerifyOnBehalfOfRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claimed_principal_id: str = Field(min_length=1, max_length=256)


class VerifyConfigIntegrityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: dict[str, Any]


class UpdateAgentIdentityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(min_length=1, max_length=32)


class IssueCredentialRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scopes: list[str] = Field(default_factory=list, max_length=50)
    ttl_seconds: int = Field(default=86400, ge=300, le=2592000)


class RotateCredentialRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    new_scopes: list[str] | None = Field(default=None, max_length=50)
    new_ttl_seconds: int = Field(default=86400, ge=300, le=2592000)


class RevokeCredentialRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="manual_revocation", max_length=256)


class IssueDelegationTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issuer_agent_id: str = Field(min_length=1, max_length=256)
    subject_agent_id: str = Field(min_length=1, max_length=256)
    delegated_scopes: list[str] = Field(min_length=1, max_length=50)
    ttl_seconds: int = Field(default=86400, ge=300, le=2592000)
    parent_token_id: str | None = Field(default=None, max_length=256)


class VerifyDelegationTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signed_token: str = Field(min_length=1, max_length=2048)


class RevokeDelegationTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="manual_revocation", max_length=256)


class RevokeAgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="manual_revocation", max_length=256)


class BulkRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_ids: list[str] = Field(min_length=1, max_length=100)
    reason: str = Field(default="security_incident", max_length=256)


class RegisterTrustedDomainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain_id: str = Field(min_length=1, max_length=256)
    display_name: str = Field(min_length=1, max_length=256)
    trust_level: str = Field(default="verified", max_length=32)
    public_key_pem: str | None = Field(default=None)
    allowed_scopes: list[str] | None = Field(default=None, max_length=50)


class CreateAttestationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain_id: str = Field(min_length=1, max_length=256)
    claims: dict[str, str] | None = Field(default=None)
    ttl_seconds: int = Field(default=86400, ge=300, le=2592000)


# --- Endpoints ---


@router.post("/agents")
def post_register_agent_identity(
    request: RegisterAgentIdentityRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if request.credential_type not in VALID_CREDENTIAL_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"invalid credential_type, must be one of: {sorted(VALID_CREDENTIAL_TYPES)}",
        )
    try:
        identity = register_agent_identity(
            agent_id=request.agent_id,
            owner=owner,
            credential_type=request.credential_type,
            public_key_pem=request.public_key_pem,
            metadata=request.metadata,
            human_principal_id=request.human_principal_id,
            configuration_checksum=request.configuration_checksum,
        )
        return dict(identity)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/agents/{agent_id}")
def get_agent_identity_endpoint(
    agent_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        identity = get_agent_identity(agent_id)
        return dict(identity)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/agents/{agent_id}")
def patch_agent_identity(
    agent_id: str,
    request: UpdateAgentIdentityRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        identity = get_agent_identity(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if identity["owner"] != owner:
        raise HTTPException(status_code=403, detail="owner mismatch")

    try:
        updated = update_agent_identity_status(agent_id, request.status)
        return dict(updated)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/agents/{agent_id}/credentials")
def post_issue_credential(
    agent_id: str,
    request: IssueCredentialRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        result = issue_credential(
            agent_id=agent_id,
            scopes=request.scopes,
            ttl_seconds=request.ttl_seconds,
            owner=owner,
        )
        return {
            "credential_id": result["credential_id"],
            "agent_id": result["agent_id"],
            "secret": result["secret"],
            "scopes": result["scopes"],
            "expires_at": iso_from_epoch(result["expires_at_epoch"]),
            "status": result["status"],
        }
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/credentials/{credential_id}/rotate")
def post_rotate_credential(
    credential_id: str,
    request: RotateCredentialRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        result = rotate_credential(
            credential_id=credential_id,
            owner=owner,
            new_scopes=request.new_scopes,
            new_ttl_seconds=request.new_ttl_seconds,
        )
        return {
            "credential_id": result["credential_id"],
            "agent_id": result["agent_id"],
            "secret": result["secret"],
            "scopes": result["scopes"],
            "expires_at": iso_from_epoch(result["expires_at_epoch"]),
            "status": result["status"],
            "rotated_from": credential_id,
        }
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/credentials/{credential_id}/revoke")
def post_revoke_credential(
    credential_id: str,
    request: RevokeCredentialRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        cred = revoke_credential(
            credential_id=credential_id,
            owner=owner,
            reason=request.reason,
        )
        return dict(cred)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/credentials/{credential_id}")
def get_credential_metadata_endpoint(
    credential_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return get_credential_metadata(credential_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/agents/{agent_id}/active-sessions")
def get_active_sessions(
    agent_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        sessions = list_active_sessions(agent_id)
        return {
            "agent_id": sessions["agent_id"],
            "credentials": [dict(c) for c in sessions["credentials"]],
        }
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# --- Blended Identity & Configuration Checksum Endpoints ---


@router.put("/agents/{agent_id}/human-principal")
def put_bind_human_principal(
    agent_id: str,
    request: BindHumanPrincipalRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        identity = get_agent_identity(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if identity["owner"] != owner:
        raise HTTPException(status_code=403, detail="owner mismatch")
    try:
        updated = bind_human_principal(agent_id, request.human_principal_id)
        return dict(updated)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put("/agents/{agent_id}/configuration-checksum")
def put_configuration_checksum(
    agent_id: str,
    request: SetConfigurationChecksumRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        identity = get_agent_identity(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if identity["owner"] != owner:
        raise HTTPException(status_code=403, detail="owner mismatch")
    try:
        updated = set_configuration_checksum(agent_id, request.checksum)
        return dict(updated)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/agents/{agent_id}/configuration-checksum/verify")
def get_verify_configuration_checksum(
    agent_id: str,
    checksum: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        identity = get_agent_identity(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    stored = identity.get("configuration_checksum")
    return {
        "agent_id": agent_id,
        "valid": stored is not None and stored == checksum,
        "stored_checksum": stored,
    }


# --- Blended Identity Endpoints ---


@router.get("/agents/{agent_id}/blended")
def get_blended_identity_endpoint(
    agent_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get the blended identity (agent + human principal) for an agent."""
    try:
        return get_blended_identity(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/agents/{agent_id}/on-behalf-of/verify")
def post_verify_on_behalf_of(
    agent_id: str,
    request: VerifyOnBehalfOfRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Verify that an agent's on-behalf-of claim matches its stored binding."""
    try:
        return verify_on_behalf_of(
            agent_id=agent_id,
            claimed_principal_id=request.claimed_principal_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# --- Config Integrity Endpoints ---


@router.post("/agents/{agent_id}/configuration-checksum/compute")
def post_compute_config_checksum(
    agent_id: str,
    request: VerifyConfigIntegrityRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Compute a config checksum from a manifest and optionally store it."""
    try:
        identity = get_agent_identity(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if identity["owner"] != owner:
        raise HTTPException(status_code=403, detail="owner mismatch")
    checksum = compute_config_checksum(request.manifest)
    return {"agent_id": agent_id, "checksum": checksum}


@router.post("/agents/{agent_id}/configuration-checksum/integrity")
def post_verify_config_integrity(
    agent_id: str,
    request: VerifyConfigIntegrityRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Verify that a manifest matches the agent's stored configuration checksum."""
    try:
        return verify_config_integrity(agent_id=agent_id, manifest=request.manifest)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# --- Delegation Token Endpoints ---


@router.post("/delegation-tokens")
def post_issue_delegation_token(
    request: IssueDelegationTokenRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        result = issue_delegation_token(
            issuer_agent_id=request.issuer_agent_id,
            subject_agent_id=request.subject_agent_id,
            delegated_scopes=request.delegated_scopes,
            ttl_seconds=request.ttl_seconds,
            parent_token_id=request.parent_token_id,
            owner=owner,
        )
        return result
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/delegation-tokens/verify")
def post_verify_delegation_token(
    request: VerifyDelegationTokenRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return verify_delegation_token(request.signed_token)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/delegation-tokens/{token_id}/chain")
def get_delegation_token_chain(
    token_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return get_delegation_chain(token_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/delegation-tokens/{token_id}/revoke")
def post_revoke_delegation_token(
    token_id: str,
    _request: RevokeDelegationTokenRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return revoke_delegation_token(token_id, owner)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


# --- Revocation & Kill Switch Endpoints ---


@router.get("/revocations")
def get_revocations(
    agent_id: str | None = None,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    events = list_revocation_events(agent_id=agent_id)
    return {"events": events}


@router.post("/revocations/bulk")
def post_bulk_revoke(
    request: BulkRevokeRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return bulk_revoke(
        agent_ids=request.agent_ids,
        owner=owner,
        reason=request.reason,
    )


@router.post("/agents/{agent_id}/revoke")
def post_revoke_agent(
    agent_id: str,
    request: RevokeAgentRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return revoke_agent(agent_id=agent_id, owner=owner, reason=request.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


# --- Trust Registry & Federation Endpoints ---


@router.post("/trust-registry/domains")
def post_register_trusted_domain(
    request: RegisterTrustedDomainRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return register_trusted_domain(
            domain_id=request.domain_id,
            display_name=request.display_name,
            trust_level=request.trust_level,
            public_key_pem=request.public_key_pem,
            allowed_scopes=request.allowed_scopes,
            registered_by=owner,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/trust-registry/domains/{domain_id}")
def get_trusted_domain_endpoint(
    domain_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return get_trusted_domain(domain_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/trust-registry/domains")
def get_trusted_domains(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return {"domains": list_trusted_domains()}


@router.post("/agents/{agent_id}/attest")
def post_create_attestation(
    agent_id: str,
    request: CreateAttestationRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return create_agent_attestation(
            agent_id=agent_id,
            domain_id=request.domain_id,
            claims=request.claims,
            ttl_seconds=request.ttl_seconds,
            owner=owner,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/attestations/{attestation_id}/verify")
def get_verify_attestation(
    attestation_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return verify_agent_attestation(attestation_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


# ── SPIFFE / SPIRE ──────────────────────────────────────────────────


class GenerateSvidRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ttl_hours: int = Field(default=24, ge=1, le=720)
    workload_path: str | None = Field(default=None, max_length=256)


class VerifySpiffeIdRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    spiffe_id: str = Field(min_length=10, max_length=512)


class SpiffeBundleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_ids: list[str] = Field(min_length=1, max_length=100)


@router.get("/agents/{agent_id}/spiffe-id")
def get_agent_spiffe_id(
    agent_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Generate the SPIFFE ID for an agent."""
    spiffe_id = generate_spiffe_id(agent_id=agent_id)
    return {"spiffe_id": spiffe_id, "agent_id": agent_id}


@router.post("/agents/{agent_id}/svid")
def post_agent_svid(
    agent_id: str,
    request: GenerateSvidRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Issue a self-signed X.509 SVID for an agent."""
    spiffe_id = generate_spiffe_id(agent_id=agent_id, workload_path=request.workload_path)
    return generate_svid(agent_id=agent_id, spiffe_id=spiffe_id, ttl_hours=request.ttl_hours)


@router.post("/spiffe/verify")
def post_verify_spiffe_id(
    request: VerifySpiffeIdRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Validate a SPIFFE ID format and extract components."""
    return verify_spiffe_id(request.spiffe_id)


@router.post("/spiffe/bundle")
def post_spiffe_bundle(
    request: SpiffeBundleRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Generate a SPIFFE trust bundle for multiple agents."""
    return generate_spiffe_bundle(request.agent_ids)
