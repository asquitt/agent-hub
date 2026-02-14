"""Provenance sign/verify manifests and artifacts routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.api.auth import require_api_key
from src.api.models import (
    ProvenanceArtifactSignRequest,
    ProvenanceArtifactVerifyRequest,
    ProvenanceManifestSignRequest,
    ProvenanceManifestVerifyRequest,
)
from src.provenance.service import (
    artifact_hash,
    manifest_hash,
    sign_artifact,
    sign_manifest,
    verify_artifact_signature,
    verify_manifest_signature,
)

router = APIRouter(tags=["provenance"])


@router.post("/v1/provenance/manifests/sign")
def post_manifest_provenance_sign(
    request: ProvenanceManifestSignRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if request.signer != owner:
        raise HTTPException(status_code=403, detail="signer must match authenticated owner")
    envelope = sign_manifest(manifest=request.manifest, signer=request.signer, artifact_hashes=request.artifact_hashes)
    return {"manifest_hash": manifest_hash(request.manifest), "envelope": envelope}


@router.post("/v1/provenance/manifests/verify")
def post_manifest_provenance_verify(
    request: ProvenanceManifestVerifyRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    verification = verify_manifest_signature(manifest=request.manifest, envelope=request.envelope)
    return {"verification": verification}


@router.post("/v1/provenance/artifacts/sign")
def post_artifact_provenance_sign(
    request: ProvenanceArtifactSignRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if request.signer != owner:
        raise HTTPException(status_code=403, detail="signer must match authenticated owner")
    envelope = sign_artifact(artifact_id=request.artifact_id, artifact_payload=request.artifact_payload, signer=request.signer)
    return {"artifact_hash": artifact_hash(request.artifact_payload), "envelope": envelope}


@router.post("/v1/provenance/artifacts/verify")
def post_artifact_provenance_verify(
    request: ProvenanceArtifactVerifyRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    verification = verify_artifact_signature(
        artifact_id=request.artifact_id,
        artifact_payload=request.artifact_payload,
        envelope=request.envelope,
    )
    return {"verification": verification}
