"""Identity advanced routes — SPIFFE/SPIRE, capability tokens.

Split from identity.py to keep under 800-line limit.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
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
