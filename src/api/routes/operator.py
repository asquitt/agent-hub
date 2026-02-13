from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from src.api.auth import require_api_key, require_scope
from src.api.operator_helpers import delegation_timeline, policy_cost_overlay, require_operator_role
from src.delegation import storage as delegation_storage
from src.discovery.service import DISCOVERY_SERVICE
from src.eval.storage import latest_result
from src.registry.store import STORE
from src.trust.scoring import compute_trust_score

router = APIRouter()


def _operator_search(query: str, tenant_id: str) -> list[dict[str, Any]]:
    result = DISCOVERY_SERVICE.semantic_discovery(query=query, constraints={}, tenant_id=tenant_id)
    return list(result.get("data", []))[:5]


@router.get("/v1/operator/dashboard")
def operator_dashboard(
    agent_id: str,
    query: str = Query(default="normalize records"),
    owner: str = Depends(require_api_key),
    x_operator_role: str | None = Header(default=None, alias="X-Operator-Role"),
) -> dict[str, Any]:
    role = require_operator_role(owner, x_operator_role, {"viewer", "admin"})

    try:
        agent = STORE.get_agent(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc

    latest = agent.versions[-1]
    eval_row = latest_result(agent_id=agent_id, version=latest.version)
    trust = compute_trust_score(agent_id=agent_id, owner=agent.owner)
    tenant_id = str(getattr(agent, "tenant_id", "tenant-default"))
    search_rows = _operator_search(query=query, tenant_id=tenant_id)

    delegations = [
        row
        for row in delegation_storage.load_records()
        if row.get("requester_agent_id") == agent_id or row.get("delegate_agent_id") == agent_id
    ]
    delegations.sort(key=lambda row: row.get("updated_at", ""), reverse=True)
    overlay = policy_cost_overlay(delegations)
    timeline = delegation_timeline(delegations, limit=80)

    return {
        "role": role,
        "agent_id": agent_id,
        "sections": {
            "search": {
                "query": query,
                "results": search_rows,
            },
            "agent_detail": {
                "namespace": agent.namespace,
                "status": agent.status,
                "latest_version": latest.version,
                "capability_count": len(latest.manifest.get("capabilities", [])),
            },
            "eval": eval_row
            or {
                "status": "pending",
                "agent_id": agent_id,
                "version": latest.version,
            },
            "trust": trust,
            "delegations": delegations[:5],
            "policy_cost_overlay": overlay,
            "timeline": timeline,
        },
    }


@router.get("/v1/operator/replay/{delegation_id}")
def operator_replay(
    delegation_id: str,
    owner: str = Depends(require_api_key),
    x_operator_role: str | None = Header(default=None, alias="X-Operator-Role"),
) -> dict[str, Any]:
    role = require_operator_role(owner, x_operator_role, {"viewer", "admin"})
    row = delegation_storage.get_record(delegation_id)
    if row is None:
        raise HTTPException(status_code=404, detail="delegation not found")
    queue_state = delegation_storage.get_queue_state(delegation_id)
    overlay = policy_cost_overlay([row])
    timeline = delegation_timeline([row], limit=200)
    return {
        "role": role,
        "delegation_id": delegation_id,
        "status": row.get("status", "unknown"),
        "queue_state": queue_state,
        "policy_decision": row.get("policy_decision"),
        "budget_controls": row.get("budget_controls"),
        "cost_overlay": overlay["totals"],
        "timeline": timeline,
    }


@router.post("/v1/operator/refresh")
def operator_refresh(
    owner: str = Depends(require_scope("operator.refresh")),
    x_operator_role: str | None = Header(default=None, alias="X-Operator-Role"),
) -> dict[str, str]:
    role = require_operator_role(owner, x_operator_role, {"admin"})
    return {"status": "refreshed", "role": role}
