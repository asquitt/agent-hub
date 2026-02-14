"""Shared helper functions used across multiple route modules."""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from fastapi import HTTPException
from fastapi.responses import JSONResponse, Response

from src.cost_governance.service import record_metering_event
from src.discovery.index import LIVE_CAPABILITY_INDEX
from src.discovery.service import DISCOVERY_SERVICE
from src.eval.storage import latest_result
from src.registry.store import STORE
from src.trust.scoring import compute_trust_score


def resolve_tenant_id(raw_tenant_id: str | None) -> str:
    if raw_tenant_id is None:
        return "tenant-default"
    normalized = raw_tenant_id.strip()
    return normalized if normalized else "tenant-default"


def require_idempotency_key(idempotency_key: str | None) -> str:
    if not idempotency_key:
        raise HTTPException(status_code=400, detail="missing Idempotency-Key header")
    return idempotency_key


def request_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def delegation_idempotency_owner(owner: str, tenant_id: str) -> str:
    return f"{owner}:{tenant_id}"


def serialize_agent(agent: Any) -> dict[str, Any]:
    latest = agent.versions[-1]
    eval_row = latest_result(agent_id=agent.agent_id, version=latest.version)
    eval_summary = eval_row["metrics"] if eval_row else {"status": "pending"}
    trust = compute_trust_score(agent_id=agent.agent_id, owner=agent.owner)
    return {
        "id": agent.agent_id,
        "tenant_id": getattr(agent, "tenant_id", "tenant-default"),
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


def is_admin_owner(owner: str) -> bool:
    return owner in {"owner-dev", "owner-platform"}


def extract_required_fields(schema: dict[str, Any]) -> list[str]:
    required = schema.get("required", [])
    if not isinstance(required, list):
        return []
    return [str(item) for item in required]


def stable_error(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"detail": {"code": code, "message": message}})


def append_warning_header(response: Response, warning: str) -> None:
    existing = response.headers.get("X-AgentHub-Deprecation-Warn")
    if existing:
        if warning not in existing:
            response.headers["X-AgentHub-Deprecation-Warn"] = f"{existing}; {warning}"
        return
    response.headers["X-AgentHub-Deprecation-Warn"] = warning


def meter_warn(
    *,
    actor: str,
    kind: str,
    method: str,
    path: str,
    tenant_id: str,
    code: str,
    message: str,
) -> None:
    record_metering_event(
        actor=actor,
        operation=kind,
        cost_usd=0.0,
        metadata={
            "method": method,
            "path": path,
            "tenant_id": tenant_id,
            "code": code,
            "message": message,
        },
    )


def constraints_from_filters(filters: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(filters, dict):
        return {}
    constraints: dict[str, Any] = {}
    for key in ("max_latency_ms", "max_cost_usd", "min_trust_score", "required_permissions", "allowed_protocols"):
        if key in filters and filters[key] is not None:
            constraints[key] = filters[key]
    return constraints


def apply_pagination(rows: list[dict[str, Any]], pagination: dict[str, Any] | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    total = len(rows)
    if not pagination:
        return rows, {"mode": "offset", "offset": 0, "limit": total, "total": total}

    mode = str(pagination.get("mode", "offset"))
    limit = int(pagination.get("limit", 20))
    limit = max(1, min(limit, 100))
    if mode == "cursor":
        cursor = str(pagination.get("cursor") or "idx:0")
        try:
            start = int(cursor.split(":", 1)[1])
        except (IndexError, ValueError):
            start = 0
        start = max(0, min(start, total))
        sliced = rows[start : start + limit]
        next_cursor = None
        if start + limit < total:
            next_cursor = f"idx:{start + limit}"
        return sliced, {
            "mode": "cursor",
            "cursor": cursor,
            "next_cursor": next_cursor,
            "limit": limit,
            "total": total,
        }

    offset = int(pagination.get("offset", 0))
    offset = max(0, min(offset, total))
    sliced = rows[offset : offset + limit]
    return sliced, {"mode": "offset", "offset": offset, "limit": limit, "total": total}


def capability_search(
    *,
    query: str,
    filters: dict[str, Any] | None = None,
    pagination: dict[str, Any] | None = None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    constraints = constraints_from_filters(filters)
    result = DISCOVERY_SERVICE.semantic_discovery(query=query, constraints=constraints, tenant_id=tenant_id)
    rows, page = apply_pagination(list(result.get("data", [])), pagination)
    return {
        **result,
        "data": rows,
        "pagination": page,
    }


def capability_match(
    *,
    input_required: list[str],
    output_required: list[str],
    compatibility_mode: str = "backward_compatible",
    filters: dict[str, Any] | None = None,
    pagination: dict[str, Any] | None = None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    constraints = constraints_from_filters(filters)
    result = DISCOVERY_SERVICE.contract_match(
        input_required=input_required,
        output_required=output_required,
        max_cost_usd=constraints.get("max_cost_usd"),
        tenant_id=tenant_id,
    )
    rows = list(result.get("data", []))
    if compatibility_mode == "exact":
        rows = [row for row in rows if str(row.get("compatibility")) == "exact"]
    max_latency = constraints.get("max_latency_ms")
    if max_latency is not None:
        rows = [row for row in rows if int(row.get("p95_latency_ms", 10**9)) <= int(max_latency)]
    rows, page = apply_pagination(rows, pagination)
    return {
        **result,
        "data": rows,
        "pagination": page,
    }


def capability_recommend(
    *,
    task_description: str,
    current_capability_ids: list[str],
    filters: dict[str, Any] | None = None,
    pagination: dict[str, Any] | None = None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    constraints = constraints_from_filters(filters)
    result = DISCOVERY_SERVICE.semantic_discovery(query=task_description, constraints=constraints, tenant_id=tenant_id)
    blocked = {str(item) for item in current_capability_ids}
    task_tokens = {token for token in task_description.lower().replace("-", " ").split() if token}
    deduped: dict[str, dict[str, Any]] = {}
    for row in list(result.get("data", [])):
        capability_id = str(row.get("capability_id"))
        if capability_id in blocked:
            continue
        corpus = " ".join(
            [
                capability_id,
                str(row.get("capability_name", "")),
                str(row.get("description", "")),
            ]
        ).lower()
        overlap = len(task_tokens.intersection({token for token in corpus.replace("-", " ").split() if token}))
        lexical_bonus = overlap / max(1, len(task_tokens))
        recommendation_score = round(float(row.get("composite_score", 0.0)) + (0.5 * lexical_bonus), 6)
        enriched = {
            **row,
            "recommendation_score": recommendation_score,
            "recommendation_reason": "task semantic match",
        }
        existing = deduped.get(capability_id)
        if existing is None or float(existing["recommendation_score"]) < recommendation_score:
            deduped[capability_id] = enriched
    rows = list(deduped.values())
    rows.sort(key=lambda item: (-float(item["recommendation_score"]), float(item.get("estimated_cost_usd", 0.0))))
    rows, page = apply_pagination(rows, pagination)
    return {
        **result,
        "data": rows,
        "pagination": page,
    }


def list_agent_capabilities(agent_id: str, tenant_id: str | None = None) -> dict[str, Any]:
    snapshot = LIVE_CAPABILITY_INDEX.snapshot()
    short_id = agent_id.split(":")[-1]
    rows = []
    for row in snapshot["rows"]:
        if row.agent_id not in {agent_id, short_id}:
            continue
        if row.visibility == "public" or (tenant_id is not None and row.tenant_id in {tenant_id, "*"}):
            rows.append(row)
    if rows:
        return {
            "agent_id": agent_id,
            "capabilities": [
                {
                    "capability_id": row.capability_id,
                    "capability_name": row.capability_name,
                    "description": row.description,
                    "protocols": list(row.protocols),
                    "permissions": list(row.permissions),
                    "input_schema": {"type": "object", "required": list(row.input_required)},
                    "output_schema": {"type": "object", "required": list(row.output_fields)},
                }
                for row in rows
            ],
        }

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


def delegate_policy_signals(delegate_agent_id: str) -> tuple[float | None, list[str]]:
    snapshot = LIVE_CAPABILITY_INDEX.snapshot()
    short_id = delegate_agent_id.split(":")[-1]
    rows = [row for row in snapshot["rows"] if row.agent_id in {delegate_agent_id, short_id}]
    if not rows:
        return None, []
    trust = max(float(row.trust_score) for row in rows)
    permissions = sorted({perm for row in rows for perm in row.permissions})
    return trust, permissions


def require_invoice_read_access(owner: str, invoice: dict[str, Any]) -> None:
    invoice_owner = str(invoice.get("owner", ""))
    if is_admin_owner(owner) or invoice_owner == owner:
        return
    raise HTTPException(status_code=403, detail="actor not permitted to view invoice")


def require_contract_read_access(owner: str, contract: dict[str, Any]) -> None:
    buyer = str(contract.get("buyer", ""))
    seller = str(contract.get("seller", ""))
    if is_admin_owner(owner) or owner in {buyer, seller}:
        return
    raise HTTPException(status_code=403, detail="actor not permitted to view contract")
