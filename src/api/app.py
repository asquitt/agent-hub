from __future__ import annotations

import copy
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse

from src.api.auth import issue_scoped_token, require_api_key, require_api_key_owner, require_scope
from src.api.manifest_validation import validate_manifest_object
from src.api.models import (
    AuthTokenIssueRequest,
    AgentForkRequest,
    AgentRegistrationRequest,
    AgentUpdateRequest,
    BillingInvoiceGenerateRequest,
    BillingRefundRequest,
    BillingSubscriptionRequest,
    BillingUsageRequest,
    CompatibilityRequest,
    ContractMatchRequest,
    DelegationRequest,
    DevHubReviewCreateRequest,
    DevHubReviewDecisionRequest,
    DiscoverySearchRequest,
    FederatedExecutionRequest,
    KnowledgeContributeRequest,
    KnowledgeValidationRequest,
    LeaseCreateRequest,
    LeasePromoteRequest,
    LeaseRollbackRequest,
    MatchRequest,
    MarketplaceListingCreateRequest,
    MarketplacePurchaseRequest,
    MarketplaceSettlementRequest,
    RecommendRequest,
    SearchRequest,
    ProvenanceArtifactSignRequest,
    ProvenanceArtifactVerifyRequest,
    ProvenanceManifestSignRequest,
    ProvenanceManifestVerifyRequest,
    TrustUsageEventRequest,
)
from src.api.store import STORE
from src.billing import (
    create_subscription,
    generate_invoice,
    get_invoice,
    reconcile_invoice,
    record_usage_event as billing_record_usage_event,
    refund_invoice,
)
from src.cost_governance.service import list_metering_events, record_metering_event
from src.delegation.service import create_delegation, delegation_contract, get_delegation_status
from src.delegation import storage as delegation_storage
from src.devhub import service as devhub_service
from src.discovery.service import DISCOVERY_SERVICE, mcp_tool_declarations
from src.eval.storage import latest_result
from src.federation import execute_federated, list_federation_audit
from src.knowledge import contribute_entry, query_entries, validate_entry
from src.lease import create_lease, get_lease, promote_lease, rollback_install
from src.marketplace import create_listing, get_contract, list_listings, purchase_listing, settle_contract
from src.policy import evaluate_delegation_policy, evaluate_install_promotion_policy
from src.provenance.service import (
    artifact_hash,
    manifest_hash,
    sign_artifact,
    sign_manifest,
    verify_artifact_signature,
    verify_manifest_signature,
)
from src.reliability.service import DEFAULT_WINDOW_SIZE, build_slo_dashboard
from src.trust.scoring import compute_trust_score, record_usage_event as trust_record_usage_event
from src.versioning import compute_behavioral_diff
from tools.capability_search.mock_engine import (
    list_agent_capabilities as mock_list_agent_capabilities,
    load_mock_capabilities,
    match_capabilities as mock_match_capabilities,
    recommend_capabilities as mock_recommend_capabilities,
    search_capabilities as mock_search_capabilities,
)

app = FastAPI(title="AgentHub Registry Service", version="0.1.0")
ROOT = Path(__file__).resolve().parents[2]
OPERATOR_ROLE_BY_OWNER = {
    "owner-dev": "admin",
    "owner-platform": "admin",
    "owner-partner": "viewer",
}
DELEGATION_IDEMPOTENCY_CACHE: dict[tuple[str, str], dict[str, Any]] = {}
DELEGATION_PENDING_WAIT_SECONDS = 4.0
DELEGATION_PENDING_POLL_SECONDS = 0.02


def _require_idempotency_key(idempotency_key: str | None) -> str:
    if not idempotency_key:
        raise HTTPException(status_code=400, detail="missing Idempotency-Key header")
    return idempotency_key


def _extract_required_fields(schema: dict[str, Any]) -> list[str]:
    required = schema.get("required", [])
    if not isinstance(required, list):
        return []
    return [str(item) for item in required]


def _request_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _delegation_idempotency_owner(owner: str, tenant_id: str) -> str:
    return f"{owner}:{tenant_id}"


def _wait_for_delegation_idempotency_response(owner: str, key: str) -> dict[str, Any] | None:
    deadline = time.monotonic() + DELEGATION_PENDING_WAIT_SECONDS
    while time.monotonic() < deadline:
        replay = delegation_storage.get_idempotency_response(owner=owner, idempotency_key=key)
        if replay is not None:
            return replay
        time.sleep(DELEGATION_PENDING_POLL_SECONDS)
    return None


def _serialize_agent(agent) -> dict[str, Any]:
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


def _cache_idempotent(owner: str, tenant_id: str, key: str, payload: dict[str, Any]) -> dict[str, Any]:
    composite = _idempotency_cache_key(owner=owner, key=key, tenant_id=tenant_id)
    if composite in STORE.idempotency_cache:
        return copy.deepcopy(STORE.idempotency_cache[composite])
    STORE.idempotency_cache[composite] = copy.deepcopy(payload)
    return payload


def _idempotency_cache_key(owner: str, key: str, tenant_id: str) -> tuple[str, str, str]:
    return (owner, tenant_id, key)


def _resolve_operator_role(owner: str, requested_role: str | None) -> str:
    assigned = OPERATOR_ROLE_BY_OWNER.get(owner, "viewer")
    if requested_role is None:
        return assigned
    if requested_role not in {"viewer", "admin"}:
        raise HTTPException(status_code=403, detail="invalid operator role")
    if requested_role == "admin" and assigned != "admin":
        raise HTTPException(status_code=403, detail="insufficient operator role")
    return requested_role


def _require_operator_role(owner: str, requested_role: str | None, allowed_roles: set[str]) -> str:
    role = _resolve_operator_role(owner, requested_role)
    if role not in allowed_roles:
        raise HTTPException(status_code=403, detail="operator role not permitted")
    return role


def _delegate_policy_signals(delegate_agent_id: str) -> tuple[float | None, list[str]]:
    short_id = delegate_agent_id.split(":")[-1]
    rows = [row for row in load_mock_capabilities() if row.get("agent_id") == short_id]
    if not rows:
        return None, []
    trust = max(float(row.get("trust_score", 0.0)) for row in rows)
    permissions = sorted({perm for row in rows for perm in row.get("permissions", [])})
    return trust, permissions


def _resolve_tenant_id(raw_tenant_id: str | None) -> str:
    if raw_tenant_id is None:
        return "tenant-default"
    normalized = raw_tenant_id.strip()
    return normalized if normalized else "tenant-default"


def _delegation_timeline(delegations: list[dict[str, Any]], limit: int = 60) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in delegations:
        delegation_id = str(row.get("delegation_id", ""))
        for stage in row.get("lifecycle", []):
            if not isinstance(stage, dict):
                continue
            events.append(
                {
                    "timestamp": stage.get("timestamp"),
                    "delegation_id": delegation_id,
                    "event_type": "lifecycle_stage",
                    "event_name": stage.get("stage"),
                    "details": stage.get("details", {}),
                }
            )
        for audit in row.get("audit_trail", []):
            if not isinstance(audit, dict):
                continue
            events.append(
                {
                    "timestamp": audit.get("timestamp"),
                    "delegation_id": delegation_id,
                    "event_type": "audit",
                    "event_name": audit.get("type", "audit"),
                    "details": audit.get("details", {}),
                }
            )

    events.sort(key=lambda item: str(item.get("timestamp", "")), reverse=True)
    return events[:limit]


def _policy_cost_overlay(delegations: list[dict[str, Any]]) -> dict[str, Any]:
    estimated_total = 0.0
    actual_total = 0.0
    hard_stop_count = 0
    pending_reauth_count = 0
    soft_alert_count = 0

    cards: list[dict[str, Any]] = []
    for row in delegations:
        estimated = float(row.get("estimated_cost_usd", 0.0) or 0.0)
        actual = float(row.get("actual_cost_usd", 0.0) or 0.0)
        estimated_total += estimated
        actual_total += actual

        status = str(row.get("status", "unknown"))
        if status == "failed_hard_stop":
            hard_stop_count += 1
        if status == "pending_reauthorization":
            pending_reauth_count += 1
        budget_controls = row.get("budget_controls", {}) if isinstance(row.get("budget_controls"), dict) else {}
        if bool(budget_controls.get("soft_alert")):
            soft_alert_count += 1

        policy_decision = row.get("policy_decision", {}) if isinstance(row.get("policy_decision"), dict) else {}
        cards.append(
            {
                "delegation_id": row.get("delegation_id"),
                "status": status,
                "updated_at": row.get("updated_at"),
                "estimated_cost_usd": round(estimated, 6),
                "actual_cost_usd": round(actual, 6),
                "budget_ratio": float(budget_controls.get("ratio", 0.0) or 0.0),
                "budget_state": budget_controls.get("state", "unknown"),
                "policy_decision": policy_decision.get("decision", "unknown"),
            }
        )

    cards.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)
    return {
        "totals": {
            "estimated_cost_usd": round(estimated_total, 6),
            "actual_cost_usd": round(actual_total, 6),
            "delegation_count": len(delegations),
            "hard_stop_count": hard_stop_count,
            "pending_reauthorization_count": pending_reauth_count,
            "soft_alert_count": soft_alert_count,
        },
        "delegation_cards": cards[:8],
    }


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/auth/tokens")
def issue_auth_token(
    request: AuthTokenIssueRequest,
    owner: str = Depends(require_api_key_owner),
) -> dict[str, Any]:
    return issue_scoped_token(owner=owner, scopes=request.scopes, ttl_seconds=request.ttl_seconds)


@app.post("/v1/provenance/manifests/sign")
def post_manifest_provenance_sign(
    request: ProvenanceManifestSignRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if request.signer != owner:
        raise HTTPException(status_code=403, detail="signer must match authenticated owner")
    envelope = sign_manifest(manifest=request.manifest, signer=request.signer, artifact_hashes=request.artifact_hashes)
    return {"manifest_hash": manifest_hash(request.manifest), "envelope": envelope}


@app.post("/v1/provenance/manifests/verify")
def post_manifest_provenance_verify(
    request: ProvenanceManifestVerifyRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    verification = verify_manifest_signature(manifest=request.manifest, envelope=request.envelope)
    return {"verification": verification}


@app.post("/v1/provenance/artifacts/sign")
def post_artifact_provenance_sign(
    request: ProvenanceArtifactSignRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if request.signer != owner:
        raise HTTPException(status_code=403, detail="signer must match authenticated owner")
    envelope = sign_artifact(artifact_id=request.artifact_id, artifact_payload=request.artifact_payload, signer=request.signer)
    return {"artifact_hash": artifact_hash(request.artifact_payload), "envelope": envelope}


@app.post("/v1/provenance/artifacts/verify")
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


@app.get("/operator", response_class=HTMLResponse)
def operator_console() -> str:
    ui_path = ROOT / "src" / "ui" / "operator_dashboard.html"
    return ui_path.read_text(encoding="utf-8")


@app.get("/operator/versioning", response_class=HTMLResponse)
def operator_versioning_console() -> str:
    ui_path = ROOT / "src" / "ui" / "version_compare.html"
    return ui_path.read_text(encoding="utf-8")


@app.post("/v1/agents")
def register_agent(
    request: AgentRegistrationRequest,
    owner: str = Depends(require_api_key),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    key = _require_idempotency_key(idempotency_key)
    tenant_id = _resolve_tenant_id(x_tenant_id)
    existing = STORE.idempotency_cache.get(_idempotency_cache_key(owner=owner, key=key, tenant_id=tenant_id))
    if existing:
        return copy.deepcopy(existing)

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

    response = _serialize_agent(agent)
    return _cache_idempotent(owner, tenant_id, key, response)


@app.get("/v1/agents")
def list_agents(
    namespace: str | None = Query(default=None),
    status: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _resolve_tenant_id(x_tenant_id)
    agents = STORE.list_agents(namespace=namespace, status=status, tenant_id=tenant_id)
    sliced = agents[offset : offset + limit]
    return {
        "data": [_serialize_agent(a) for a in sliced],
        "pagination": {"mode": "offset", "offset": offset, "limit": limit, "total": len(agents)},
    }


@app.get("/v1/agents/{agent_id}/versions")
def list_versions(agent_id: str, x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID")) -> dict[str, Any]:
    tenant_id = _resolve_tenant_id(x_tenant_id)
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


@app.get("/v1/agents/{agent_id}/versions/{version}")
def get_version(
    agent_id: str,
    version: str,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _resolve_tenant_id(x_tenant_id)
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


@app.get("/v1/agents/{agent_id}/versions/{base_version}/behavioral-diff/{target_version}")
def get_behavioral_diff(
    agent_id: str,
    base_version: str,
    target_version: str,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _resolve_tenant_id(x_tenant_id)
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


@app.get("/v1/agents/{agent_id}/compare/{base_version}/{target_version}")
def compare_versions(
    agent_id: str,
    base_version: str,
    target_version: str,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _resolve_tenant_id(x_tenant_id)
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


@app.post("/v1/agents/{agent_id}/fork")
def fork_agent(
    agent_id: str,
    request: AgentForkRequest,
    owner: str = Depends(require_api_key),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    key = _require_idempotency_key(idempotency_key)
    tenant_id = _resolve_tenant_id(x_tenant_id)
    existing = STORE.idempotency_cache.get(_idempotency_cache_key(owner=owner, key=key, tenant_id=tenant_id))
    if existing:
        return copy.deepcopy(existing)

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

    response = {
        "source_agent_id": agent_id,
        "forked_agent": _serialize_agent(forked),
    }
    return _cache_idempotent(owner, tenant_id, key, response)


@app.get("/v1/namespaces/{namespace}")
def list_namespace_agents(namespace: str, x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID")) -> dict[str, Any]:
    ns = namespace if namespace.startswith("@") else f"@{namespace}"
    tenant_id = _resolve_tenant_id(x_tenant_id)
    agents = STORE.list_agents(namespace=ns, tenant_id=tenant_id)
    return {
        "namespace": ns,
        "data": [_serialize_agent(a) for a in agents],
    }


@app.post("/v1/capabilities/search")
def search_capabilities(request: SearchRequest) -> dict[str, Any]:
    try:
        result = mock_search_capabilities(
            query=request.query,
            filters=request.filters.model_dump(exclude_none=True) if request.filters else None,
            pagination=request.pagination.model_dump(exclude_none=True) if request.pagination else None,
            ranking_weights=request.ranking_weights,
        )
        record_metering_event(
            actor="runtime.search",
            operation="capabilities.search",
            cost_usd=max(0.0002, 0.00005 * len(result.get("data", []))),
            metadata={"query": request.query, "result_count": len(result.get("data", []))},
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/v1/capabilities/match")
def match_capabilities(request: MatchRequest) -> dict[str, Any]:
    try:
        result = mock_match_capabilities(
            input_required=_extract_required_fields(request.input_schema),
            output_required=_extract_required_fields(request.output_schema),
            compatibility_mode=request.filters.compatibility_mode if request.filters else "backward_compatible",
            filters=request.filters.model_dump(exclude_none=True) if request.filters else None,
            pagination=request.pagination.model_dump(exclude_none=True) if request.pagination else None,
        )
        record_metering_event(
            actor="runtime.search",
            operation="capabilities.match",
            cost_usd=max(0.00015, 0.00005 * len(result.get("data", []))),
            metadata={"result_count": len(result.get("data", []))},
        )
        return result
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
        result = mock_recommend_capabilities(
            task_description=request.task_description,
            current_capability_ids=request.current_capability_ids,
            filters=request.filters.model_dump(exclude_none=True) if request.filters else None,
            pagination=request.pagination.model_dump(exclude_none=True) if request.pagination else None,
            ranking_weights=request.ranking_weights,
        )
        record_metering_event(
            actor="runtime.search",
            operation="capabilities.recommend",
            cost_usd=max(0.0002, 0.00005 * len(result.get("data", []))),
            metadata={"result_count": len(result.get("data", []))},
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/v1/discovery/search")
def discovery_search(request: DiscoverySearchRequest) -> dict[str, Any]:
    return DISCOVERY_SERVICE.semantic_discovery(query=request.query, constraints=request.constraints or {})


@app.post("/v1/discovery/contract-match")
def discovery_contract_match(request: ContractMatchRequest) -> dict[str, Any]:
    constraints = request.constraints or {}
    return DISCOVERY_SERVICE.contract_match(
        input_required=[str(x) for x in request.input_schema.get("required", [])],
        output_required=[str(x) for x in request.output_schema.get("required", [])],
        max_cost_usd=constraints.get("max_cost_usd"),
    )


@app.post("/v1/discovery/compatibility")
def discovery_compatibility(request: CompatibilityRequest) -> dict[str, Any]:
    return DISCOVERY_SERVICE.compatibility_report(my_schema=request.my_schema, agent_id=request.agent_id)


@app.get("/v1/discovery/mcp-tools")
def discovery_mcp_tools() -> dict[str, Any]:
    return {"tools": mcp_tool_declarations()}


@app.get("/v1/discovery/agent-manifest")
def discovery_agent_manifest(agent_id: str, version: str | None = None) -> dict[str, Any]:
    try:
        agent = STORE.get_agent(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc

    if version:
        try:
            record = STORE.get_version(agent_id, version)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="version not found") from exc
        return {"agent_id": agent_id, "version": version, "manifest": record.manifest}

    latest = agent.versions[-1]
    return {"agent_id": agent_id, "version": latest.version, "manifest": latest.manifest}


@app.get("/.well-known/agent-card.json")
def discovery_agent_card() -> dict[str, Any]:
    card_path = ROOT / ".well-known" / "agent-card.json"
    return json.loads(card_path.read_text(encoding="utf-8"))


@app.get("/v1/operator/dashboard")
def operator_dashboard(
    agent_id: str,
    query: str = Query(default="normalize records"),
    owner: str = Depends(require_api_key),
    x_operator_role: str | None = Header(default=None, alias="X-Operator-Role"),
) -> dict[str, Any]:
    role = _require_operator_role(owner, x_operator_role, {"viewer", "admin"})

    try:
        agent = STORE.get_agent(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc

    latest = agent.versions[-1]
    eval_row = latest_result(agent_id=agent_id, version=latest.version)
    trust = compute_trust_score(agent_id=agent_id, owner=agent.owner)

    search_payload = mock_search_capabilities(
        query=query,
        pagination={"mode": "offset", "offset": 0, "limit": 5},
    )

    delegations = [
        row
        for row in delegation_storage.load_records()
        if row.get("requester_agent_id") == agent_id or row.get("delegate_agent_id") == agent_id
    ]
    delegations.sort(key=lambda row: row.get("updated_at", ""), reverse=True)
    overlay = _policy_cost_overlay(delegations)
    timeline = _delegation_timeline(delegations, limit=80)

    return {
        "role": role,
        "agent_id": agent_id,
        "sections": {
            "search": {
                "query": query,
                "results": search_payload.get("data", []),
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


@app.get("/v1/operator/replay/{delegation_id}")
def operator_replay(
    delegation_id: str,
    owner: str = Depends(require_api_key),
    x_operator_role: str | None = Header(default=None, alias="X-Operator-Role"),
) -> dict[str, Any]:
    role = _require_operator_role(owner, x_operator_role, {"viewer", "admin"})
    row = delegation_storage.get_record(delegation_id)
    if row is None:
        raise HTTPException(status_code=404, detail="delegation not found")
    queue_state = delegation_storage.get_queue_state(delegation_id)
    overlay = _policy_cost_overlay([row])
    timeline = _delegation_timeline([row], limit=200)
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


@app.post("/v1/operator/refresh")
def operator_refresh(
    owner: str = Depends(require_scope("operator.refresh")),
    x_operator_role: str | None = Header(default=None, alias="X-Operator-Role"),
) -> dict[str, str]:
    role = _require_operator_role(owner, x_operator_role, {"admin"})
    return {"status": "refreshed", "role": role}


@app.post("/v1/devhub/reviews")
def post_devhub_review(
    request: DevHubReviewCreateRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        _ = STORE.get_version(request.agent_id, request.version)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent version not found") from exc
    return devhub_service.create_release_review(
        agent_id=request.agent_id,
        version=request.version,
        requested_by=owner,
        approvals_required=request.approvals_required,
    )


@app.get("/v1/devhub/reviews")
def list_devhub_reviews(
    agent_id: str | None = Query(default=None),
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return {"data": devhub_service.list_release_reviews(agent_id=agent_id)}


@app.get("/v1/devhub/reviews/{review_id}")
def get_devhub_review(review_id: str, _owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        return devhub_service.get_release_review(review_id=review_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="review not found") from exc


@app.post("/v1/devhub/reviews/{review_id}/decision")
def post_devhub_review_decision(
    review_id: str,
    request: DevHubReviewDecisionRequest,
    owner: str = Depends(require_api_key),
    x_operator_role: str | None = Header(default=None, alias="X-Operator-Role"),
) -> dict[str, Any]:
    _ = _require_operator_role(owner, x_operator_role, {"admin"})
    try:
        return devhub_service.decide_release_review(
            review_id=review_id,
            actor=owner,
            decision=request.decision,
            note=request.note,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="review not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/devhub/reviews/{review_id}/promote")
def post_devhub_review_promote(
    review_id: str,
    owner: str = Depends(require_api_key),
    x_operator_role: str | None = Header(default=None, alias="X-Operator-Role"),
) -> dict[str, Any]:
    _ = _require_operator_role(owner, x_operator_role, {"admin"})
    try:
        return devhub_service.promote_release_review(review_id=review_id, promoted_by=owner)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="review not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/devhub/promotions")
def get_devhub_promotions(
    agent_id: str | None = Query(default=None),
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return {"data": devhub_service.list_promotions(agent_id=agent_id)}


@app.post("/v1/capabilities/lease")
def post_capability_lease(request: LeaseCreateRequest, owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        lease = create_lease(
            requester_agent_id=request.requester_agent_id,
            capability_ref=request.capability_ref,
            owner=owner,
            ttl_seconds=request.ttl_seconds,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return lease


@app.get("/v1/capabilities/leases/{lease_id}")
def get_capability_lease(lease_id: str, owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        return get_lease(lease_id=lease_id, owner=owner)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="lease not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.post("/v1/capabilities/leases/{lease_id}/promote")
def post_capability_promote(
    lease_id: str,
    request: LeasePromoteRequest,
    owner: str = Depends(require_api_key),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _resolve_tenant_id(x_tenant_id)
    policy_decision = evaluate_install_promotion_policy(
        actor="runtime.install",
        owner=owner,
        lease_id=lease_id,
        policy_approved=request.policy_approved,
        attestation_hash=request.attestation_hash,
        signature=request.signature,
        abac_context={
            "principal": {
                "owner": owner,
                "tenant_id": tenant_id,
                "allowed_actions": ["promote_lease"],
                "mfa_present": True,
            },
            "resource": {"tenant_id": tenant_id},
            "environment": {"requires_mfa": False},
        },
    )
    if not policy_decision["allowed"]:
        record_metering_event(
            actor=owner,
            operation="capabilities.lease_promote_denied",
            cost_usd=0.0,
            metadata={"lease_id": lease_id, "violations": policy_decision["violated_constraints"]},
        )
        raise HTTPException(
            status_code=403,
            detail={
                "message": "policy denied install promotion",
                "policy_decision": policy_decision,
            },
        )

    try:
        promoted = promote_lease(
            lease_id=lease_id,
            owner=owner,
            signature=request.signature,
            attestation_hash=request.attestation_hash,
            policy_approved=request.policy_approved,
            approval_ticket=request.approval_ticket,
            compatibility_verified=request.compatibility_verified,
        )
        record_metering_event(
            actor=owner,
            operation="capabilities.lease_promote",
            cost_usd=0.0003,
            metadata={"lease_id": lease_id, "status": promoted.get("status")},
        )
        promoted["policy_decision"] = policy_decision
        return promoted
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="lease not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/capabilities/installs/{install_id}/rollback")
def post_install_rollback(
    install_id: str,
    request: LeaseRollbackRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        rolled_back = rollback_install(install_id=install_id, owner=owner, reason=request.reason)
        record_metering_event(
            actor=owner,
            operation="capabilities.install_rollback",
            cost_usd=0.0001,
            metadata={"install_id": install_id},
        )
        return rolled_back
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="install not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.post("/v1/knowledge/contribute")
def post_knowledge_contribution(
    request: KnowledgeContributeRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return contribute_entry(
            owner=owner,
            title=request.title,
            content=request.content,
            tags=request.tags,
            source_uri=request.source_uri,
            contributor=request.contributor,
            base_confidence=request.base_confidence,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/knowledge/query")
def get_knowledge_query(
    q: str = Query(min_length=2),
    limit: int = Query(default=10, ge=1, le=50),
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return {"query": q, "data": query_entries(query=q, limit=limit)}


@app.post("/v1/knowledge/validate/{entry_id}")
def post_knowledge_validation(
    entry_id: str,
    request: KnowledgeValidationRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return validate_entry(entry_id=entry_id, validator=owner, verdict=request.verdict, rationale=request.rationale)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="entry not found") from exc


@app.post("/v1/billing/subscriptions")
def post_billing_subscription(
    request: BillingSubscriptionRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return create_subscription(
        account_id=request.account_id,
        plan_id=request.plan_id,
        owner=owner,
        monthly_fee_usd=request.monthly_fee_usd,
        included_units=request.included_units,
    )


@app.post("/v1/billing/usage")
def post_billing_usage(
    request: BillingUsageRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return billing_record_usage_event(
        account_id=request.account_id,
        meter=request.meter,
        quantity=request.quantity,
        unit_price_usd=request.unit_price_usd,
        owner=owner,
    )


@app.post("/v1/billing/invoices/generate")
def post_billing_generate_invoice(
    request: BillingInvoiceGenerateRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return generate_invoice(account_id=request.account_id, owner=owner)


@app.get("/v1/billing/invoices/{invoice_id}")
def get_billing_invoice(invoice_id: str, _owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        return get_invoice(invoice_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="invoice not found") from exc


@app.post("/v1/billing/invoices/{invoice_id}/reconcile")
def post_billing_reconcile(invoice_id: str, _owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        return reconcile_invoice(invoice_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="invoice not found") from exc


@app.post("/v1/billing/invoices/{invoice_id}/refund")
def post_billing_refund(
    invoice_id: str,
    request: BillingRefundRequest,
    owner: str = Depends(require_scope("billing.refund")),
) -> dict[str, Any]:
    if owner != "owner-platform":
        raise HTTPException(status_code=403, detail="billing admin role required")
    try:
        return refund_invoice(
            invoice_id=invoice_id,
            amount_usd=request.amount_usd,
            reason=request.reason,
            actor=owner,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="invoice not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/marketplace/listings")
def post_marketplace_listing(
    request: MarketplaceListingCreateRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        listing = create_listing(
            owner=owner,
            capability_ref=request.capability_ref,
            unit_price_usd=request.unit_price_usd,
            max_units_per_purchase=request.max_units_per_purchase,
            policy_purchase_limit_usd=request.policy_purchase_limit_usd,
        )
        record_metering_event(actor=owner, operation="marketplace.listing_create", cost_usd=0.0, metadata={"listing_id": listing["listing_id"]})
        return listing
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/marketplace/listings")
def get_marketplace_listings(_owner: str = Depends(require_api_key)) -> dict[str, Any]:
    return {"data": list_listings()}


@app.post("/v1/marketplace/purchase")
def post_marketplace_purchase(
    request: MarketplacePurchaseRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        contract = purchase_listing(
            buyer=owner,
            listing_id=request.listing_id,
            units=request.units,
            max_total_usd=request.max_total_usd,
            policy_approved=request.policy_approved,
        )
        record_metering_event(actor=owner, operation="marketplace.purchase", cost_usd=contract["estimated_total_usd"], metadata={"contract_id": contract["contract_id"]})
        return contract
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="listing not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/marketplace/contracts/{contract_id}")
def get_marketplace_contract(contract_id: str, _owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        return get_contract(contract_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="contract not found") from exc


@app.post("/v1/marketplace/contracts/{contract_id}/settle")
def post_marketplace_settlement(
    contract_id: str,
    request: MarketplaceSettlementRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        settled = settle_contract(contract_id=contract_id, actor=owner, units_used=request.units_used)
        record_metering_event(actor=owner, operation="marketplace.settle", cost_usd=0.0, metadata={"contract_id": contract_id})
        return settled
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="contract not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/delegations")
def post_delegation(
    request: DelegationRequest,
    owner: str = Depends(require_api_key),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    key = _require_idempotency_key(idempotency_key)
    request_payload = request.model_dump(mode="json")
    request_digest = _request_hash(request_payload)
    tenant_id = _resolve_tenant_id(x_tenant_id)
    idempotency_owner = _delegation_idempotency_owner(owner=owner, tenant_id=tenant_id)
    reservation = delegation_storage.reserve_idempotency(
        owner=idempotency_owner,
        idempotency_key=key,
        request_hash=request_digest,
    )
    reservation_state = str(reservation.get("state"))
    if reservation_state == "mismatch":
        raise HTTPException(status_code=409, detail="idempotency key replay with different request payload")
    if reservation_state == "response":
        return copy.deepcopy(reservation["response"])
    if reservation_state == "pending":
        replay = _wait_for_delegation_idempotency_response(owner=idempotency_owner, key=key)
        if replay is not None:
            return replay
        reservation = delegation_storage.reserve_idempotency(
            owner=idempotency_owner,
            idempotency_key=key,
            request_hash=request_digest,
        )
        reservation_state = str(reservation.get("state"))
        if reservation_state == "mismatch":
            raise HTTPException(status_code=409, detail="idempotency key replay with different request payload")
        if reservation_state == "response":
            return copy.deepcopy(reservation["response"])
        if reservation_state == "pending":
            raise HTTPException(status_code=409, detail="idempotency key request already in progress")

    owns_reservation = reservation_state == "reserved"
    if not owns_reservation:
        raise HTTPException(status_code=500, detail="unable to reserve idempotency slot")

    sre_dashboard = build_slo_dashboard(window_size=DEFAULT_WINDOW_SIZE)
    circuit_breaker = sre_dashboard["circuit_breaker"]
    if circuit_breaker["state"] == "open":
        delegation_storage.clear_idempotency(owner=idempotency_owner, idempotency_key=key)
        raise HTTPException(
            status_code=503,
            detail={
                "message": "delegation circuit breaker is open",
                "circuit_breaker": circuit_breaker,
                "alerts": sre_dashboard["alerts"],
            },
        )

    delegate_trust_score, delegate_permissions = _delegate_policy_signals(request.delegate_agent_id)
    try:
        policy_decision = evaluate_delegation_policy(
            actor="runtime.delegation",
            requester_agent_id=request.requester_agent_id,
            delegate_agent_id=request.delegate_agent_id,
            estimated_cost_usd=request.estimated_cost_usd,
            max_budget_usd=request.max_budget_usd,
            auto_reauthorize=request.auto_reauthorize,
            min_delegate_trust_score=request.min_delegate_trust_score,
            delegate_trust_score=delegate_trust_score,
            required_permissions=request.required_permissions,
            delegate_permissions=delegate_permissions,
            abac_context={
                "principal": {
                    "owner": owner,
                    "tenant_id": tenant_id,
                    "allowed_actions": ["create_delegation"],
                    "mfa_present": True,
                },
                "resource": {"tenant_id": tenant_id},
                "environment": {"requires_mfa": False},
            },
        )
        if not policy_decision["allowed"]:
            status = 400 if all(code.startswith("budget.") for code in policy_decision["violated_constraints"]) else 403
            raise HTTPException(
                status_code=status,
                detail={
                    "message": "policy denied delegation",
                    "policy_decision": policy_decision,
                },
            )

        row = create_delegation(
            requester_agent_id=request.requester_agent_id,
            delegate_agent_id=request.delegate_agent_id,
            task_spec=request.task_spec,
            estimated_cost_usd=request.estimated_cost_usd,
            max_budget_usd=request.max_budget_usd,
            simulated_actual_cost_usd=request.simulated_actual_cost_usd,
            auto_reauthorize=request.auto_reauthorize,
            policy_decision=policy_decision,
            metering_events=request.metering_events,
        )
        response = {
            "contract": delegation_contract(),
            "delegation_id": row["delegation_id"],
            "status": row["status"],
            "budget_controls": row["budget_controls"],
            "policy_decision": policy_decision,
            "lifecycle": row["lifecycle"],
            "queue_state": row.get("queue_state"),
            "sre_governance": {
                "circuit_breaker": circuit_breaker,
                "alerts": sre_dashboard["alerts"],
            },
        }
    except ValueError as exc:
        delegation_storage.clear_idempotency(owner=idempotency_owner, idempotency_key=key)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HTTPException:
        delegation_storage.clear_idempotency(owner=idempotency_owner, idempotency_key=key)
        raise
    except Exception:
        delegation_storage.clear_idempotency(owner=idempotency_owner, idempotency_key=key)
        raise

    delegation_storage.finalize_idempotency(owner=idempotency_owner, idempotency_key=key, response=response)
    DELEGATION_IDEMPOTENCY_CACHE[(owner, key)] = {
        "request_hash": request_digest,
        "response": copy.deepcopy(response),
    }
    return response


@app.get("/v1/delegations/contract")
def get_delegation_contract_endpoint(_owner: str = Depends(require_api_key)) -> dict[str, Any]:
    return delegation_contract()


@app.get("/v1/cost/metering")
def get_cost_metering_endpoint(limit: int = Query(default=50, ge=1, le=500), _owner: str = Depends(require_api_key)) -> dict[str, Any]:
    return {"data": list_metering_events(limit=limit)}


@app.get("/v1/reliability/slo-dashboard")
def get_reliability_slo_dashboard(
    window_size: int = Query(default=50, ge=1, le=1000),
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return build_slo_dashboard(window_size=window_size)


@app.post("/v1/federation/execute")
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


@app.get("/v1/federation/audit")
def get_federation_audit(limit: int = Query(default=50, ge=1, le=500), _owner: str = Depends(require_api_key)) -> dict[str, Any]:
    return {"data": list_federation_audit(limit=limit)}


@app.get("/v1/delegations/{delegation_id}/status")
def get_delegation_status_endpoint(delegation_id: str) -> dict[str, Any]:
    row = get_delegation_status(delegation_id)
    if not row:
        raise HTTPException(status_code=404, detail="delegation not found")
    return row


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

    trust_record_usage_event(
        agent_id=agent.agent_id,
        success=request.success,
        cost_usd=request.cost_usd,
        latency_ms=request.latency_ms,
    )
    return compute_trust_score(agent_id=agent.agent_id, owner=agent.owner)


@app.get("/v1/agents/{agent_id}")
def get_agent(agent_id: str, x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID")) -> dict[str, Any]:
    tenant_id = _resolve_tenant_id(x_tenant_id)
    try:
        agent = STORE.get_agent(agent_id, tenant_id=tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc
    return _serialize_agent(agent)


@app.put("/v1/agents/{agent_id}")
def update_agent(
    agent_id: str,
    request: AgentUpdateRequest,
    owner: str = Depends(require_api_key),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    key = _require_idempotency_key(idempotency_key)
    tenant_id = _resolve_tenant_id(x_tenant_id)
    existing = STORE.idempotency_cache.get(_idempotency_cache_key(owner=owner, key=key, tenant_id=tenant_id))
    if existing:
        return copy.deepcopy(existing)

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

    response = _serialize_agent(agent)
    return _cache_idempotent(owner, tenant_id, key, response)


@app.delete("/v1/agents/{agent_id}")
def delete_agent(
    agent_id: str,
    owner: str = Depends(require_api_key),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    key = _require_idempotency_key(idempotency_key)
    tenant_id = _resolve_tenant_id(x_tenant_id)
    existing = STORE.idempotency_cache.get(_idempotency_cache_key(owner=owner, key=key, tenant_id=tenant_id))
    if existing:
        return copy.deepcopy(existing)

    try:
        agent = STORE.delete_agent(agent_id, owner, tenant_id=tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    response = {"id": agent.agent_id, "status": agent.status}
    return _cache_idempotent(owner, tenant_id, key, response)
