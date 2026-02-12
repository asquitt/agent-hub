from __future__ import annotations

import copy
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query

from src.api.auth import require_api_key
from src.api.manifest_validation import validate_manifest_object
from src.api.models import (
    AgentRegistrationRequest,
    AgentUpdateRequest,
    MatchRequest,
    RecommendRequest,
    SearchRequest,
    TrustUsageEventRequest,
)
from src.api.store import STORE
from src.eval.storage import latest_result
from src.trust.scoring import compute_trust_score, record_usage_event
from tools.capability_search.mock_engine import (
    list_agent_capabilities as mock_list_agent_capabilities,
    match_capabilities as mock_match_capabilities,
    recommend_capabilities as mock_recommend_capabilities,
    search_capabilities as mock_search_capabilities,
)

app = FastAPI(title="AgentHub Registry Service", version="0.1.0")


def _require_idempotency_key(idempotency_key: str | None) -> str:
    if not idempotency_key:
        raise HTTPException(status_code=400, detail="missing Idempotency-Key header")
    return idempotency_key


def _extract_required_fields(schema: dict[str, Any]) -> list[str]:
    required = schema.get("required", [])
    if not isinstance(required, list):
        return []
    return [str(item) for item in required]


def _serialize_agent(agent) -> dict[str, Any]:
    latest = agent.versions[-1]
    eval_row = latest_result(agent_id=agent.agent_id, version=latest.version)
    eval_summary = eval_row["metrics"] if eval_row else {"status": "pending"}
    trust = compute_trust_score(agent_id=agent.agent_id, owner=agent.owner)
    return {
        "id": agent.agent_id,
        "namespace": agent.namespace,
        "slug": agent.slug,
        "status": agent.status,
        "latest_version": latest.version,
        "manifest": latest.manifest,
        "eval_summary": eval_summary,
        "trust": {
            "score": trust["score"],
            "tier": trust["tier"],
            "badge": trust["badge"],
        },
        "versions": [v.version for v in agent.versions],
    }


def _cache_idempotent(owner: str, key: str, payload: dict[str, Any]) -> dict[str, Any]:
    composite = (owner, key)
    if composite in STORE.idempotency_cache:
        return copy.deepcopy(STORE.idempotency_cache[composite])
    STORE.idempotency_cache[composite] = copy.deepcopy(payload)
    return payload


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/agents")
def register_agent(
    request: AgentRegistrationRequest,
    owner: str = Depends(require_api_key),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    key = _require_idempotency_key(idempotency_key)
    existing = STORE.idempotency_cache.get((owner, key))
    if existing:
        return copy.deepcopy(existing)

    errors = validate_manifest_object(request.manifest)
    if errors:
        raise HTTPException(status_code=422, detail={"message": "manifest validation failed", "errors": errors})

    try:
        STORE.reserve_namespace(request.namespace, owner)
        agent = STORE.register_agent(request.namespace, request.manifest, owner)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    response = _serialize_agent(agent)
    return _cache_idempotent(owner, key, response)


@app.get("/v1/agents")
def list_agents(
    namespace: str | None = Query(default=None),
    status: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
) -> dict[str, Any]:
    agents = STORE.list_agents(namespace=namespace, status=status)
    sliced = agents[offset : offset + limit]
    return {
        "data": [_serialize_agent(a) for a in sliced],
        "pagination": {"mode": "offset", "offset": offset, "limit": limit, "total": len(agents)},
    }


@app.get("/v1/agents/{agent_id}/versions")
def list_versions(agent_id: str) -> dict[str, Any]:
    try:
        versions = STORE.list_versions(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc

    return {
        "agent_id": agent_id,
        "versions": [
            {
                "version": v.version,
                "published": True,
                "eval_summary": (latest_result(agent_id=agent_id, version=v.version) or {}).get("metrics", {"status": "pending"}),
            }
            for v in versions
        ],
    }


@app.get("/v1/agents/{agent_id}/versions/{version}")
def get_version(agent_id: str, version: str) -> dict[str, Any]:
    try:
        record = STORE.get_version(agent_id, version)
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


@app.get("/v1/namespaces/{namespace}")
def list_namespace_agents(namespace: str) -> dict[str, Any]:
    ns = namespace if namespace.startswith("@") else f"@{namespace}"
    agents = STORE.list_agents(namespace=ns)
    return {
        "namespace": ns,
        "data": [_serialize_agent(a) for a in agents],
    }


@app.post("/v1/capabilities/search")
def search_capabilities(request: SearchRequest) -> dict[str, Any]:
    try:
        return mock_search_capabilities(
            query=request.query,
            filters=request.filters.model_dump(exclude_none=True) if request.filters else None,
            pagination=request.pagination.model_dump(exclude_none=True) if request.pagination else None,
            ranking_weights=request.ranking_weights,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/v1/capabilities/match")
def match_capabilities(request: MatchRequest) -> dict[str, Any]:
    try:
        return mock_match_capabilities(
            input_required=_extract_required_fields(request.input_schema),
            output_required=_extract_required_fields(request.output_schema),
            compatibility_mode=request.filters.compatibility_mode if request.filters else "backward_compatible",
            filters=request.filters.model_dump(exclude_none=True) if request.filters else None,
            pagination=request.pagination.model_dump(exclude_none=True) if request.pagination else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/v1/agents/{agent_id}/capabilities")
def list_agent_capabilities(agent_id: str) -> dict[str, Any]:
    # Agent-native mock catalog for discovery + registered in-memory fallback.
    short_id = agent_id.split(":")[-1]
    try:
        return mock_list_agent_capabilities(short_id)
    except ValueError:
        try:
            agent = STORE.get_agent(agent_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="agent not found") from exc

        latest = agent.versions[-1].manifest
        return {
            "agent_id": agent_id,
            "capabilities": [
                {
                    "capability_id": c["id"],
                    "capability_name": c["name"],
                    "description": c["description"],
                    "protocols": c["protocols"],
                    "permissions": c.get("permissions", []),
                    "input_schema": c["input_schema"],
                    "output_schema": c["output_schema"],
                }
                for c in latest.get("capabilities", [])
            ],
        }


@app.post("/v1/capabilities/recommend")
def recommend_capabilities(request: RecommendRequest) -> dict[str, Any]:
    try:
        return mock_recommend_capabilities(
            task_description=request.task_description,
            current_capability_ids=request.current_capability_ids,
            filters=request.filters.model_dump(exclude_none=True) if request.filters else None,
            pagination=request.pagination.model_dump(exclude_none=True) if request.pagination else None,
            ranking_weights=request.ranking_weights,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/v1/agents/{agent_id}/trust")
def get_agent_trust(agent_id: str) -> dict[str, Any]:
    try:
        agent = STORE.get_agent(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc
    return compute_trust_score(agent_id=agent.agent_id, owner=agent.owner)


@app.post("/v1/agents/{agent_id}/trust/usage")
def post_usage_event(
    agent_id: str,
    request: TrustUsageEventRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        agent = STORE.get_agent(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc

    record_usage_event(
        agent_id=agent.agent_id,
        success=request.success,
        cost_usd=request.cost_usd,
        latency_ms=request.latency_ms,
    )
    return compute_trust_score(agent_id=agent.agent_id, owner=agent.owner)


@app.get("/v1/agents/{agent_id}")
def get_agent(agent_id: str) -> dict[str, Any]:
    try:
        agent = STORE.get_agent(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc
    return _serialize_agent(agent)


@app.put("/v1/agents/{agent_id}")
def update_agent(
    agent_id: str,
    request: AgentUpdateRequest,
    owner: str = Depends(require_api_key),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    key = _require_idempotency_key(idempotency_key)
    existing = STORE.idempotency_cache.get((owner, key))
    if existing:
        return copy.deepcopy(existing)

    errors = validate_manifest_object(request.manifest)
    if errors:
        raise HTTPException(status_code=422, detail={"message": "manifest validation failed", "errors": errors})

    try:
        agent = STORE.update_agent(agent_id, request.manifest, owner)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    response = _serialize_agent(agent)
    return _cache_idempotent(owner, key, response)


@app.delete("/v1/agents/{agent_id}")
def delete_agent(
    agent_id: str,
    owner: str = Depends(require_api_key),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    key = _require_idempotency_key(idempotency_key)
    existing = STORE.idempotency_cache.get((owner, key))
    if existing:
        return copy.deepcopy(existing)

    try:
        agent = STORE.delete_agent(agent_id, owner)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    response = {"id": agent.agent_id, "status": agent.status}
    return _cache_idempotent(owner, key, response)
