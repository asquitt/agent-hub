"""Identity advanced routes — SPIFFE/SPIRE, capability tokens, lifecycle.

Split from identity.py to keep under 800-line limit.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.identity.analytics import (
    get_credential_statistics,
    get_delegation_statistics,
    get_identity_health_score,
    get_identity_statistics,
)
from src.identity.did import (
    create_did,
    deactivate_did,
    issue_verifiable_credential,
    list_dids,
    list_verifiable_credentials,
    resolve_did,
    revoke_verifiable_credential,
    verify_verifiable_credential,
)
from src.identity.lifecycle import (
    check_expiry_alerts,
    check_rotation_due,
    deprovision_agent,
    get_lifecycle_status,
    provision_agent,
    rotate_credential as lifecycle_rotate,
)
from src.identity.capability_tokens import (
    add_third_party_block,
    attenuate_token,
    issue_capability_token,
    verify_capability_token,
)
from src.identity.spiffe import (
    generate_bundle as generate_spiffe_bundle,
    generate_spiffe_id,
    generate_svid,
    verify_spiffe_id,
)

router = APIRouter(prefix="/v1/identity", tags=["identity"])


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


# ── Capability Tokens ───────────────────────────────────────────────


class IssueCapabilityTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    issuer_agent_id: str = Field(min_length=1, max_length=256)
    subject_agent_id: str = Field(min_length=1, max_length=256)
    scopes: list[str] = Field(min_length=1, max_length=50)
    caveats: list[dict[str, Any]] | None = None
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    facts: dict[str, Any] | None = None


class AttenuateCapabilityTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: dict[str, Any]
    scopes: list[str] | None = None
    caveats: list[dict[str, Any]] | None = None
    attenuator_agent_id: str = Field(min_length=1, max_length=256)


class VerifyCapabilityTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: dict[str, Any]
    required_scope: str | None = None
    source_ip: str | None = None
    resource: str | None = None


class ThirdPartyBlockRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: dict[str, Any]
    verifier_id: str = Field(min_length=1, max_length=256)
    verification_data: dict[str, Any] = Field(default_factory=dict)


@router.post("/capability-tokens/issue")
def post_issue_capability_token(
    request: IssueCapabilityTokenRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Issue a new capability token with an authority block."""
    try:
        return issue_capability_token(
            issuer_agent_id=request.issuer_agent_id,
            subject_agent_id=request.subject_agent_id,
            scopes=request.scopes,
            caveats=request.caveats,
            ttl_seconds=request.ttl_seconds,
            facts=request.facts,
        )
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/capability-tokens/attenuate")
def post_attenuate_capability_token(
    request: AttenuateCapabilityTokenRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Attenuate a capability token by adding restrictions."""
    try:
        return attenuate_token(
            request.token,
            scopes=request.scopes,
            caveats=request.caveats,
            attenuator_agent_id=request.attenuator_agent_id,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/capability-tokens/verify")
def post_verify_capability_token(
    request: VerifyCapabilityTokenRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Verify a capability token's signatures and caveats."""
    try:
        return verify_capability_token(
            request.token,
            required_scope=request.required_scope,
            source_ip=request.source_ip,
            resource=request.resource,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/capability-tokens/third-party-block")
def post_add_third_party_block(
    request: ThirdPartyBlockRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Add a third-party verification block to a capability token."""
    try:
        return add_third_party_block(
            request.token,
            verifier_id=request.verifier_id,
            verification_data=request.verification_data,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ── Lifecycle Orchestration ─────────────────────────────────────────


class ProvisionAgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1, max_length=256)
    credential_type: str = Field(default="api_key", max_length=32)
    scopes: list[str] | None = None
    ttl_seconds: int = Field(default=86400, ge=300, le=2592000)
    metadata: dict[str, str] | None = None
    auto_rotate: bool = False
    rotation_interval_seconds: int = Field(default=86400, ge=300, le=2592000)


class RotateCredentialRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    new_scopes: list[str] | None = None
    new_ttl_seconds: int = Field(default=86400, ge=300, le=2592000)
    reason: str = Field(default="scheduled_rotation", max_length=256)


class DeprovisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(default="manual", max_length=256)


@router.post("/lifecycle/provision")
def post_provision_agent(
    request: ProvisionAgentRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Full provisioning workflow: register identity + issue credential."""
    try:
        return provision_agent(
            agent_id=request.agent_id,
            owner=owner,
            credential_type=request.credential_type,
            scopes=request.scopes,
            ttl_seconds=request.ttl_seconds,
            metadata=request.metadata,
            auto_rotate=request.auto_rotate,
            rotation_interval_seconds=request.rotation_interval_seconds,
        )
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/lifecycle/agents/{agent_id}/rotate")
def post_rotate_credential(
    agent_id: str,
    request: RotateCredentialRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Rotate an agent's credential."""
    try:
        return lifecycle_rotate(
            agent_id=agent_id,
            owner=owner,
            new_scopes=request.new_scopes,
            new_ttl_seconds=request.new_ttl_seconds,
            reason=request.reason,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/lifecycle/alerts/expiry")
def get_expiry_alerts(
    agent_id: str | None = None,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Check for credential expiry alerts."""
    return {"alerts": check_expiry_alerts(agent_id)}


@router.get("/lifecycle/alerts/rotation")
def get_rotation_due(
    agent_id: str | None = None,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Check for credentials due for rotation."""
    return {"due": check_rotation_due(agent_id)}


@router.get("/lifecycle/agents/{agent_id}/status")
def get_agent_lifecycle_status(
    agent_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get lifecycle status for an agent."""
    try:
        return get_lifecycle_status(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/lifecycle/agents/{agent_id}/deprovision")
def post_deprovision_agent(
    agent_id: str,
    request: DeprovisionRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Deprovision an agent: revoke credentials and mark inactive."""
    try:
        return deprovision_agent(agent_id=agent_id, owner=owner, reason=request.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ── Identity Analytics ──────────────────────────────────────────────


@router.get("/analytics/credentials")
def get_analytics_credentials(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get credential usage statistics."""
    return get_credential_statistics()


@router.get("/analytics/identities")
def get_analytics_identities(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get agent identity statistics."""
    return get_identity_statistics()


@router.get("/analytics/delegations")
def get_analytics_delegations(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get delegation token statistics."""
    return get_delegation_statistics()


@router.get("/analytics/health")
def get_analytics_health(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get overall identity system health score."""
    return get_identity_health_score()


# ── DIDs & Verifiable Credentials ─────────────────────────────────


class CreateDidRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1, max_length=256)
    controller: str | None = Field(default=None, max_length=512)
    service_endpoints: list[dict[str, str]] | None = None


class IssueVcRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    issuer_did: str = Field(min_length=10, max_length=512)
    subject_did: str = Field(min_length=10, max_length=512)
    credential_type: str = Field(default="AgentIdentityCredential", max_length=64)
    claims: dict[str, Any] | None = None
    ttl_seconds: int = Field(default=86400, ge=60, le=2592000)


class DeactivateDidRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(default="manual", max_length=256)


class RevokeVcRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(default="manual", max_length=256)


@router.post("/dids")
def post_create_did(
    request: CreateDidRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Create a DID Document for an agent."""
    return create_did(
        agent_id=request.agent_id,
        controller=request.controller,
        service_endpoints=request.service_endpoints,
    )


@router.get("/dids/{did_suffix}/resolve")
def get_resolve_did(
    did_suffix: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Resolve a DID to its DID Document."""
    did = f"did:agenthub:{did_suffix}"
    try:
        return resolve_did(did)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/dids/{did_suffix}/deactivate")
def post_deactivate_did(
    did_suffix: str,
    request: DeactivateDidRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Deactivate a DID."""
    did = f"did:agenthub:{did_suffix}"
    try:
        return deactivate_did(did, reason=request.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/dids")
def get_list_dids(
    active_only: bool = True,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List all DID documents."""
    dids = list_dids(active_only=active_only)
    return {"count": len(dids), "dids": dids}


@router.post("/vcs/issue")
def post_issue_vc(
    request: IssueVcRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Issue a Verifiable Credential."""
    try:
        return issue_verifiable_credential(
            issuer_did=request.issuer_did,
            subject_did=request.subject_did,
            credential_type=request.credential_type,
            claims=request.claims,
            ttl_seconds=request.ttl_seconds,
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/vcs/{vc_id}/verify")
def get_verify_vc(
    vc_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Verify a Verifiable Credential."""
    try:
        return verify_verifiable_credential(f"urn:uuid:{vc_id}")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/vcs/{vc_id}/revoke")
def post_revoke_vc(
    vc_id: str,
    request: RevokeVcRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Revoke a Verifiable Credential."""
    try:
        return revoke_verifiable_credential(f"urn:uuid:{vc_id}", reason=request.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/vcs")
def get_list_vcs(
    issuer_did: str | None = None,
    subject_did: str | None = None,
    credential_type: str | None = None,
    active_only: bool = True,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List verifiable credentials."""
    vcs = list_verifiable_credentials(
        issuer_did=issuer_did,
        subject_did=subject_did,
        credential_type=credential_type,
        active_only=active_only,
    )
    return {"count": len(vcs), "credentials": vcs}
