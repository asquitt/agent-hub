"""Agent CRUD, versions, compare, fork, capabilities, trust routes."""
from __future__ import annotations

import copy
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from src.api.auth import require_api_key
from src.api.manifest_validation import validate_manifest_object
from src.api.models import AgentForkRequest, AgentRegistrationRequest, AgentUpdateRequest, TrustUsageEventRequest
from src.api.route_helpers import list_agent_capabilities, resolve_tenant_id, serialize_agent
from src.registry.store import STORE
from src.trust.scoring import compute_trust_score, record_usage_event as trust_record_usage_event
from src.versioning import compute_behavioral_diff
from src.eval.storage import latest_result

router = APIRouter(tags=["agents"])


@router.post("/v1/agents")
def register_agent(
    request: AgentRegistrationRequest,
    owner: str = Depends(require_api_key),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(x_tenant_id)

    errors = validate_manifest_object(request.manifest)
    if errors:
        raise HTTPException(status_code=422, detail={"message": "manifest validation failed", "errors": errors})

    try:
        STORE.reserve_namespace(request.namespace, owner, tenant_id=tenant_id)
        agent = STORE.register_agent(request.namespace, request.manifest, owner, tenant_id=tenant_id)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return serialize_agent(agent)


@router.get("/v1/agents")
def list_agents(
    namespace: str | None = Query(default=None),
    status: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(x_tenant_id)
    agents = STORE.list_agents(namespace=namespace, status=status, tenant_id=tenant_id)
    sliced = agents[offset : offset + limit]
    return {
        "data": [serialize_agent(a) for a in sliced],
        "pagination": {"mode": "offset", "offset": offset, "limit": limit, "total": len(agents)},
    }


@router.get("/v1/agents/{agent_id}")
def get_agent(agent_id: str, x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID")) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(x_tenant_id)
    try:
        agent = STORE.get_agent(agent_id, tenant_id=tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc
    return serialize_agent(agent)


@router.put("/v1/agents/{agent_id}")
def update_agent(
    agent_id: str,
    request: AgentUpdateRequest,
    owner: str = Depends(require_api_key),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(x_tenant_id)

    errors = validate_manifest_object(request.manifest)
    if errors:
        raise HTTPException(status_code=422, detail={"message": "manifest validation failed", "errors": errors})

    try:
        agent = STORE.update_agent(agent_id, request.manifest, owner, tenant_id=tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return serialize_agent(agent)


@router.delete("/v1/agents/{agent_id}")
def delete_agent(
    agent_id: str,
    owner: str = Depends(require_api_key),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(x_tenant_id)

    try:
        agent = STORE.delete_agent(agent_id, owner, tenant_id=tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    return {"id": agent.agent_id, "status": agent.status}


@router.get("/v1/agents/{agent_id}/versions")
def list_versions(agent_id: str, x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID")) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(x_tenant_id)
    try:
        versions = STORE.list_versions(agent_id, tenant_id=tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc

    return {
        "agent_id": agent_id,
        "versions": [
            {
                "version": v.version,
                "published": True,
                "eval_summary": (latest_result(agent_id=agent_id, version=v.version) or {}).get("metrics", {"status": "pending"}),
                "behavioral_impact_from_previous": (
                    compute_behavioral_diff(versions[idx - 1].manifest, v.manifest) if idx > 0 else None
                ),
            }
            for idx, v in enumerate(versions)
        ],
    }


@router.get("/v1/agents/{agent_id}/versions/{version}")
def get_version(
    agent_id: str,
    version: str,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(x_tenant_id)
    try:
        record = STORE.get_version(agent_id, version, tenant_id=tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="version not found") from exc

    eval_row = latest_result(agent_id=agent_id, version=version)
    eval_summary = eval_row["metrics"] if eval_row else record.eval_summary

    return {
        "agent_id": agent_id,
        "version": record.version,
        "manifest": record.manifest,
        "eval_summary": eval_summary,
    }


@router.get("/v1/agents/{agent_id}/versions/{base_version}/behavioral-diff/{target_version}")
def get_behavioral_diff(
    agent_id: str,
    base_version: str,
    target_version: str,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(x_tenant_id)
    try:
        base = STORE.get_version(agent_id, base_version, tenant_id=tenant_id)
        target = STORE.get_version(agent_id, target_version, tenant_id=tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="version not found") from exc

    return {
        "agent_id": agent_id,
        "base_version": base_version,
        "target_version": target_version,
        "diff": compute_behavioral_diff(base.manifest, target.manifest),
    }


@router.get("/v1/agents/{agent_id}/compare/{base_version}/{target_version}")
def compare_versions(
    agent_id: str,
    base_version: str,
    target_version: str,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(x_tenant_id)
    try:
        base = STORE.get_version(agent_id, base_version, tenant_id=tenant_id)
        target = STORE.get_version(agent_id, target_version, tenant_id=tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="version not found") from exc

    base_eval = (latest_result(agent_id=agent_id, version=base_version) or {}).get("metrics", {})
    target_eval = (latest_result(agent_id=agent_id, version=target_version) or {}).get("metrics", {})
    metric_keys = sorted(set(base_eval.keys()).union(target_eval.keys()))
    eval_delta = {
        key: round(float(target_eval.get(key, 0.0)) - float(base_eval.get(key, 0.0)), 6)
        for key in metric_keys
        if isinstance(base_eval.get(key, 0.0), (int, float)) and isinstance(target_eval.get(key, 0.0), (int, float))
    }

    return {
        "agent_id": agent_id,
        "base_version": base_version,
        "target_version": target_version,
        "behavioral_diff": compute_behavioral_diff(base.manifest, target.manifest),
        "eval_base": base_eval,
        "eval_target": target_eval,
        "eval_delta": eval_delta,
    }


@router.post("/v1/agents/{agent_id}/fork")
def fork_agent(
    agent_id: str,
    request: AgentForkRequest,
    owner: str = Depends(require_api_key),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(x_tenant_id)

    try:
        source = STORE.get_agent(agent_id, tenant_id=tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc

    latest_manifest = copy.deepcopy(source.versions[-1].manifest)
    latest_manifest["identity"]["id"] = request.new_slug

    errors = validate_manifest_object(latest_manifest)
    if errors:
        raise HTTPException(status_code=422, detail={"message": "manifest validation failed", "errors": errors})

    try:
        STORE.reserve_namespace(request.namespace, owner, tenant_id=tenant_id)
        forked = STORE.register_agent(request.namespace, latest_manifest, owner, tenant_id=tenant_id)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return {
        "source_agent_id": agent_id,
        "forked_agent": serialize_agent(forked),
    }


@router.get("/v1/namespaces/{namespace}")
def list_namespace_agents(namespace: str, x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID")) -> dict[str, Any]:
    ns = namespace if namespace.startswith("@") else f"@{namespace}"
    tenant_id = resolve_tenant_id(x_tenant_id)
    agents = STORE.list_agents(namespace=ns, tenant_id=tenant_id)
    return {
        "namespace": ns,
        "data": [serialize_agent(a) for a in agents],
    }


@router.get("/v1/agents/{agent_id}/capabilities")
def get_agent_capabilities(
    agent_id: str,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    return list_agent_capabilities(agent_id, tenant_id=resolve_tenant_id(x_tenant_id))


@router.get("/v1/agents/{agent_id}/trust")
def get_agent_trust(
    agent_id: str,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(x_tenant_id)
    try:
        agent = STORE.get_agent(agent_id, tenant_id=tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc
    return compute_trust_score(agent_id=agent.agent_id, owner=agent.owner)


@router.post("/v1/agents/{agent_id}/trust/usage")
def post_usage_event(
    agent_id: str,
    request: TrustUsageEventRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        agent = STORE.get_agent(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc

    trust_record_usage_event(
        agent_id=agent.agent_id,
        success=request.success,
        cost_usd=request.cost_usd,
        latency_ms=request.latency_ms,
    )
    return compute_trust_score(agent_id=agent.agent_id, owner=agent.owner)
