"""Federation execute, domains, audit, attestation export routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.auth import require_api_key
from src.api.models import FederatedExecutionRequest
from src.cost_governance.service import record_metering_event
from src.federation import (
    execute_federated,
    export_attestation_bundle,
    list_domain_profiles,
    list_federation_audit,
)

router = APIRouter(tags=["federation"])


@router.post("/v1/federation/execute")
def post_federated_execute(request: FederatedExecutionRequest, owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        result = execute_federated(
            actor=owner,
            domain_id=request.domain_id,
            domain_token=request.domain_token,
            task_spec=request.task_spec,
            payload=request.payload,
            policy_context=request.policy_context,
            estimated_cost_usd=request.estimated_cost_usd,
            max_budget_usd=request.max_budget_usd,
            requested_residency_region=request.requested_residency_region,
            connection_mode=request.connection_mode,
            agent_attestation_id=request.agent_attestation_id,
        )
        record_metering_event(
            actor=owner,
            operation="federation.execute",
            cost_usd=request.estimated_cost_usd,
            metadata={"domain_id": request.domain_id},
        )
        return result
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/federation/domains")
def get_federation_domains(_owner: str = Depends(require_api_key)) -> dict[str, Any]:
    return {"data": list_domain_profiles()}


@router.get("/v1/federation/audit")
def get_federation_audit(limit: int = Query(default=50, ge=1, le=500), _owner: str = Depends(require_api_key)) -> dict[str, Any]:
    return {"data": list_federation_audit(limit=limit)}


@router.get("/v1/federation/attestations/export")
def get_federation_attestation_export(
    domain_id: str | None = Query(default=None, min_length=3),
    limit: int = Query(default=250, ge=1, le=1000),
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if owner not in {"owner-dev", "owner-platform"}:
        raise HTTPException(status_code=403, detail="federation compliance export requires admin role")
    return export_attestation_bundle(actor=owner, domain_id=domain_id, limit=limit)
