"""Federation execute, domains, audit, attestation export, mesh routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.api.models import FederatedExecutionRequest
from src.cost_governance.service import record_metering_event
from src.federation import (
    execute_federated,
    export_attestation_bundle,
    list_domain_profiles,
    list_federation_audit,
)
from src.federation.mesh import (
    add_mesh_policy,
    check_connection,
    deregister_node,
    get_connection_log,
    get_mesh_topology,
    heartbeat,
    list_nodes,
    register_node,
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


# ── Mesh Networking Endpoints ────────────────────────────────────


class RegisterNodeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(..., min_length=1)
    spiffe_id: str = Field(..., min_length=1)
    endpoint: str = Field(..., min_length=1)
    capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class AddMeshPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_agent_id: str = Field(..., min_length=1)
    target_agent_id: str = Field(..., min_length=1)
    policy: str = Field(default="allow")
    scopes: list[str] = Field(default_factory=list)
    ttl_seconds: int = Field(default=86400, ge=60, le=2592000)


class CheckConnectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_agent_id: str = Field(..., min_length=1)
    target_agent_id: str = Field(..., min_length=1)
    scope: str | None = None


@router.post("/v1/federation/mesh/nodes")
def post_mesh_register_node(
    request: RegisterNodeRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Register an agent as a mesh node."""
    return register_node(
        agent_id=request.agent_id,
        spiffe_id=request.spiffe_id,
        endpoint=request.endpoint,
        capabilities=request.capabilities,
        metadata=request.metadata,
    )


@router.post("/v1/federation/mesh/nodes/{node_id}/heartbeat")
def post_mesh_heartbeat(
    node_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Update mesh node heartbeat."""
    try:
        return heartbeat(node_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/federation/mesh/nodes/{node_id}/deregister")
def post_mesh_deregister_node(
    node_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Deregister a mesh node."""
    try:
        return deregister_node(node_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/v1/federation/mesh/nodes")
def get_mesh_nodes(
    active_only: bool = True,
    capability: str | None = None,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List mesh nodes."""
    nodes = list_nodes(active_only=active_only, capability=capability)
    return {"count": len(nodes), "nodes": nodes}


@router.post("/v1/federation/mesh/policies")
def post_mesh_policy(
    request: AddMeshPolicyRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Add a mesh networking policy."""
    try:
        return add_mesh_policy(
            source_agent_id=request.source_agent_id,
            target_agent_id=request.target_agent_id,
            policy=request.policy,
            scopes=request.scopes,
            ttl_seconds=request.ttl_seconds,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/v1/federation/mesh/check")
def post_mesh_check_connection(
    request: CheckConnectionRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Check if a connection is allowed (deny-by-default)."""
    return check_connection(
        source_agent_id=request.source_agent_id,
        target_agent_id=request.target_agent_id,
        scope=request.scope,
    )


@router.get("/v1/federation/mesh/connections")
def get_mesh_connections(
    agent_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get mesh connection audit log."""
    logs = get_connection_log(agent_id=agent_id, limit=limit)
    return {"count": len(logs), "connections": logs}


@router.get("/v1/federation/mesh/topology")
def get_mesh_topology_endpoint(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get mesh network topology summary."""
    return get_mesh_topology()
