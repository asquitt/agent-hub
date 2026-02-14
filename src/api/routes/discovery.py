"""Discovery search, contract-match, compatibility, MCP tools, agent manifest, inventory routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from src.api.auth import require_api_key
from src.api.models import CompatibilityRequest, ContractMatchRequest, DiscoverySearchRequest
from src.api.route_helpers import resolve_tenant_id
from src.discovery.service import DISCOVERY_SERVICE, mcp_tool_declarations
from src.identity.discovery import (
    detect_shadow_agents,
    get_agent_inventory,
    get_agent_profile,
    get_security_posture_summary,
)
from src.registry.store import STORE

router = APIRouter(tags=["discovery"])


@router.post("/v1/discovery/search")
def discovery_search(
    request: DiscoverySearchRequest,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    return DISCOVERY_SERVICE.semantic_discovery(
        query=request.query,
        constraints=request.constraints or {},
        tenant_id=resolve_tenant_id(x_tenant_id),
    )


@router.post("/v1/discovery/contract-match")
def discovery_contract_match(
    request: ContractMatchRequest,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    constraints = request.constraints or {}
    return DISCOVERY_SERVICE.contract_match(
        input_required=[str(x) for x in request.input_schema.get("required", [])],
        output_required=[str(x) for x in request.output_schema.get("required", [])],
        max_cost_usd=constraints.get("max_cost_usd"),
        tenant_id=resolve_tenant_id(x_tenant_id),
    )


@router.post("/v1/discovery/compatibility")
def discovery_compatibility(
    request: CompatibilityRequest,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    return DISCOVERY_SERVICE.compatibility_report(
        my_schema=request.my_schema,
        agent_id=request.agent_id,
        tenant_id=resolve_tenant_id(x_tenant_id),
    )


@router.get("/v1/discovery/mcp-tools")
def discovery_mcp_tools() -> dict[str, Any]:
    return {"tools": mcp_tool_declarations()}


@router.get("/v1/discovery/agent-manifest")
def discovery_agent_manifest(
    agent_id: str,
    version: str | None = None,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(x_tenant_id)
    try:
        agent = STORE.get_agent(agent_id, tenant_id=tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc

    if version:
        try:
            record = STORE.get_version(agent_id, version, tenant_id=tenant_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="version not found") from exc
        return {"agent_id": agent_id, "version": version, "manifest": record.manifest}

    latest = agent.versions[-1]
    return {"agent_id": agent_id, "version": latest.version, "manifest": latest.manifest}


# ── Agent Inventory & Security Posture ────────────────────────────


@router.get("/v1/discovery/inventory")
def discovery_inventory(
    owner: str | None = Query(default=None),
    status: str | None = Query(default=None),
    include_credentials: bool = Query(default=False),
    include_lifecycle: bool = Query(default=False),
    include_posture: bool = Query(default=False),
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Unified agent inventory across identity and registry stores."""
    return get_agent_inventory(
        owner=owner,
        status_filter=status,
        include_credentials=include_credentials,
        include_lifecycle=include_lifecycle,
        include_posture=include_posture,
    )


@router.get("/v1/discovery/inventory/{agent_id}")
def discovery_agent_profile(
    agent_id: str,
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Comprehensive profile for a single agent."""
    profile = get_agent_profile(agent_id)
    if profile.get("identity") is None and profile.get("registry") is None:
        raise HTTPException(status_code=404, detail="agent not found in any store")
    return profile


@router.get("/v1/discovery/shadow-agents")
def discovery_shadow_agents(
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Detect agents in registry without IAM identities."""
    return detect_shadow_agents()


@router.get("/v1/discovery/posture")
def discovery_posture(
    _caller: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Platform-wide security posture summary."""
    return get_security_posture_summary()
