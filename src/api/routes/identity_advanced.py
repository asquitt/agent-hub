"""Identity advanced routes — SPIFFE/SPIRE, capability tokens, lifecycle.

Split from identity.py to keep under 800-line limit.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.api.auth import AuthContext, require_api_key
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
    get_capability_token,
    issue_capability_token,
    list_capability_tokens,
    revoke_capability_token,
    verify_capability_token,
)
from src.identity.spiffe import (
    generate_bundle as generate_spiffe_bundle,
    generate_spiffe_id,
    generate_svid,
    verify_spiffe_id,
)
from src.identity.pqc import (
    generate_keypair as pqc_generate_keypair,
    get_keypair_info,
    list_keypairs,
    sign_data as pqc_sign_data,
    verify_signature as pqc_verify_signature,
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
    spiffe_id = generate_spiffe_id(
        agent_id=agent_id, workload_path=request.workload_path
    )
    return generate_svid(
        agent_id=agent_id, spiffe_id=spiffe_id, ttl_hours=request.ttl_hours
    )


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
    audience: str = Field(min_length=1, max_length=512)
    resource: str = Field(min_length=1, max_length=1024)

    @field_validator("caveats")
    @classmethod
    def validate_caveats(
        cls,
        caveats: list[dict[str, Any]] | None,
    ) -> list[dict[str, Any]] | None:
        if caveats is None:
            return None
        for caveat in caveats:
            caveat_type = caveat.get("type")
            list_field = (
                {
                    "ip": "allowed_ips",
                    "resource": "resources",
                    "scope": "scopes",
                    "agent": "agent_ids",
                }.get(caveat_type)
                if isinstance(caveat_type, str)
                else None
            )
            if list_field is not None:
                values = caveat.get(list_field)
                if (
                    not isinstance(values, list)
                    or not values
                    or any(
                        not isinstance(value, str) or not value.strip()
                        for value in values
                    )
                ):
                    raise ValueError(
                        f"{caveat_type} caveat requires non-empty {list_field}"
                    )
            elif caveat_type == "time":
                if not isinstance(caveat.get("not_after"), (int, float)):
                    raise ValueError("time caveat requires numeric not_after")
            else:
                raise ValueError("unsupported capability caveat type")
        return caveats


class AttenuateCapabilityTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: dict[str, Any] = Field(min_length=1)
    scopes: list[str] | None = None
    caveats: list[dict[str, Any]] | None = None
    attenuator_agent_id: str = Field(min_length=1, max_length=256)


class VerifyCapabilityTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: dict[str, Any] = Field(min_length=1)
    required_scope: str | None = None
    audience: str | None = Field(default=None, min_length=1, max_length=512)
    resource: str | None = Field(default=None, min_length=1, max_length=1024)


class ThirdPartyBlockRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: dict[str, Any]
    verifier_id: str = Field(min_length=1, max_length=256)
    verification_data: dict[str, Any] = Field(default_factory=dict)


class RevokeCapabilityTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(default="manual", min_length=1, max_length=256)


@router.post("/capability-tokens/issue")
def post_issue_capability_token(
    request: IssueCapabilityTokenRequest,
    actor: AuthContext = Depends(require_api_key),
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
            audience=request.audience,
            resource=request.resource,
            actor=actor,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, PermissionError) as exc:
        status = 403 if isinstance(exc, PermissionError) else 400
        raise HTTPException(status_code=status, detail=str(exc)) from exc


@router.post("/capability-tokens/attenuate")
def post_attenuate_capability_token(
    request: AttenuateCapabilityTokenRequest,
    actor: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    """Attenuate a capability token by adding restrictions."""
    try:
        return attenuate_token(
            request.token,
            scopes=request.scopes,
            caveats=request.caveats,
            attenuator_agent_id=request.attenuator_agent_id,
            actor=actor,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/capability-tokens/verify")
def post_verify_capability_token(
    request: VerifyCapabilityTokenRequest,
    http_request: Request,
    actor: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    """Verify a capability token's signatures and caveats."""
    try:
        return verify_capability_token(
            request.token,
            required_scope=request.required_scope,
            source_ip=http_request.client.host
            if http_request.client is not None
            else None,
            audience=request.audience,
            resource=request.resource,
            actor=actor,
        )
    except KeyError:
        return {"valid": False, "reason": "capability token not found"}
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/capability-tokens/third-party-block")
def post_add_third_party_block(
    request: ThirdPartyBlockRequest,
    actor: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    """Add a third-party verification block to a capability token."""
    try:
        return add_third_party_block(
            request.token,
            verifier_id=request.verifier_id,
            verification_data=request.verification_data,
            actor=actor,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/capability-tokens")
def get_list_capability_tokens(
    active_only: bool = True,
    actor: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    tokens = list_capability_tokens(actor=actor, active_only=active_only)
    return {"count": len(tokens), "tokens": tokens}


@router.get("/capability-tokens/{token_id}")
def get_capability_token_record(
    token_id: str,
    actor: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return get_capability_token(token_id, actor=actor)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/capability-tokens/{token_id}/revoke")
def post_revoke_capability_token(
    token_id: str,
    request: RevokeCapabilityTokenRequest,
    actor: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return revoke_capability_token(token_id, actor=actor, reason=request.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


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


class DidServiceEndpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(default="AgentService", min_length=1, max_length=128)
    endpoint: str = Field(min_length=1, max_length=2048)


class CreateDidRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1, max_length=256)
    controller: str | None = Field(default=None, max_length=512)
    service_endpoints: list[DidServiceEndpoint] | None = Field(
        default=None, max_length=20
    )


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
    actor: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    """Create a DID Document for an agent."""
    try:
        return create_did(
            agent_id=request.agent_id,
            controller=request.controller,
            service_endpoints=(
                [endpoint.model_dump() for endpoint in request.service_endpoints]
                if request.service_endpoints is not None
                else None
            ),
            actor=actor,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        status = 409 if "deactivated" in str(exc) else 400
        raise HTTPException(status_code=status, detail=str(exc)) from exc


@router.get("/dids/{did_suffix}/resolve")
def get_resolve_did(
    did_suffix: str,
    actor: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    """Resolve a DID to its DID Document."""
    did = f"did:agenthub:{did_suffix}"
    try:
        return resolve_did(did, actor=actor)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/dids/{did_suffix}/deactivate")
def post_deactivate_did(
    did_suffix: str,
    request: DeactivateDidRequest,
    actor: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    """Deactivate a DID."""
    did = f"did:agenthub:{did_suffix}"
    try:
        return deactivate_did(did, actor=actor, reason=request.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/dids")
def get_list_dids(
    active_only: bool = True,
    actor: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    """List all DID documents."""
    dids = list_dids(actor=actor, active_only=active_only)
    return {"count": len(dids), "dids": dids}


@router.post("/vcs/issue")
def post_issue_vc(
    request: IssueVcRequest,
    actor: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    """Issue a Verifiable Credential."""
    try:
        return issue_verifiable_credential(
            issuer_did=request.issuer_did,
            subject_did=request.subject_did,
            credential_type=request.credential_type,
            claims=request.claims,
            ttl_seconds=request.ttl_seconds,
            actor=actor,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/vcs/{vc_id}/verify")
def get_verify_vc(
    vc_id: str,
    actor: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    """Verify a Verifiable Credential."""
    try:
        return verify_verifiable_credential(f"urn:uuid:{vc_id}", actor=actor)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/vcs/{vc_id}/revoke")
def post_revoke_vc(
    vc_id: str,
    request: RevokeVcRequest,
    actor: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    """Revoke a Verifiable Credential."""
    try:
        return revoke_verifiable_credential(
            f"urn:uuid:{vc_id}",
            actor=actor,
            reason=request.reason,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/vcs")
def get_list_vcs(
    issuer_did: str | None = None,
    subject_did: str | None = None,
    credential_type: str | None = None,
    active_only: bool = True,
    actor: AuthContext = Depends(require_api_key),
) -> dict[str, Any]:
    """List verifiable credentials."""
    vcs = list_verifiable_credentials(
        issuer_did=issuer_did,
        subject_did=subject_did,
        credential_type=credential_type,
        active_only=active_only,
        actor=actor,
    )
    return {"count": len(vcs), "credentials": vcs}


# ── PQC (Post-Quantum Cryptography) Endpoints ───────────────────


class PqcGenerateKeypairRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(..., min_length=1)
    algorithm: str = Field(default="hybrid-hmac-dilithium3")


class PqcSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(..., min_length=1)
    data: dict[str, Any] = Field(...)


class PqcVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(..., min_length=1)
    data: dict[str, Any] = Field(...)
    classical_signature: str = Field(..., min_length=1)
    pq_signature: str = Field(..., min_length=1)


@router.post("/pqc/keypairs")
def post_pqc_generate_keypair(
    request: PqcGenerateKeypairRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Generate a hybrid classical+PQ key pair."""
    try:
        return pqc_generate_keypair(
            agent_id=request.agent_id,
            algorithm=request.algorithm,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/pqc/keypairs/{agent_id}")
def get_pqc_keypair(
    agent_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get PQC keypair public info for an agent."""
    try:
        return get_keypair_info(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/pqc/keypairs")
def get_pqc_keypairs(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List all PQC keypairs."""
    kps = list_keypairs()
    return {"count": len(kps), "keypairs": kps}


@router.post("/pqc/sign")
def post_pqc_sign(
    request: PqcSignRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Sign data with hybrid classical+PQ signature."""
    try:
        return pqc_sign_data(agent_id=request.agent_id, data=request.data)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/pqc/verify")
def post_pqc_verify(
    request: PqcVerifyRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Verify a hybrid classical+PQ signature."""
    try:
        return pqc_verify_signature(
            agent_id=request.agent_id,
            data=request.data,
            classical_signature=request.classical_signature,
            pq_signature=request.pq_signature,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
