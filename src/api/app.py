from __future__ import annotations

import copy
import hashlib
import json
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response

from src.api.access_policy import access_mode, classify_route, evaluate_access, requires_idempotency
from src.api.auth import (
    issue_scoped_token,
    require_api_key,
    require_api_key_owner,
    require_scope,
    resolve_owner_from_headers,
    validate_auth_configuration,
)
from src.api.operator_helpers import delegation_timeline, policy_cost_overlay, require_operator_role
from src.api.routes import customer_router, operator_router, system_router
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
    ComplianceEvidenceExportRequest,
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
    MarketplaceDisputeCreateRequest,
    MarketplaceDisputeResolveRequest,
    MarketplaceSettlementRequest,
    ProcurementApprovalCreateRequest,
    ProcurementApprovalDecisionRequest,
    ProcurementExceptionCreateRequest,
    ProcurementPolicyPackUpsertRequest,
    RecommendRequest,
    SearchRequest,
    ProvenanceArtifactSignRequest,
    ProvenanceArtifactVerifyRequest,
    ProvenanceManifestSignRequest,
    ProvenanceManifestVerifyRequest,
    TrustUsageEventRequest,
)
from src.billing import (
    create_subscription,
    generate_invoice,
    get_invoice,
    reconcile_invoice,
    record_usage_event as billing_record_usage_event,
    refund_invoice,
)
from src.cost_governance.service import list_metering_events, record_metering_event
from src.compliance import export_evidence_pack, list_controls as list_compliance_controls, list_evidence_reports
from src.delegation.service import create_delegation, delegation_contract, get_delegation_status
from src.delegation import storage as delegation_storage
from src.devhub import service as devhub_service
from src.discovery.service import DISCOVERY_SERVICE, mcp_tool_declarations
from src.eval.storage import latest_result
from src.federation import (
    execute_federated,
    export_attestation_bundle,
    list_domain_profiles,
    list_federation_audit,
    validate_federation_configuration,
)
from src.idempotency import storage as idempotency_storage
from src.knowledge import contribute_entry, query_entries, validate_entry
from src.lease import create_lease, get_lease, promote_lease, rollback_install
from src.marketplace import create_listing, get_contract, list_listings, purchase_listing, settle_contract
from src.marketplace import create_dispute, create_payout, list_disputes, list_payouts, resolve_dispute
from src.policy import evaluate_delegation_policy, evaluate_install_promotion_policy
from src.procurement import (
    create_approval_request,
    create_exception,
    decide_approval,
    list_approvals,
    list_audit_events as list_procurement_audit_events,
    list_exceptions,
    list_policy_packs,
    upsert_policy_pack,
)
from src.provenance.service import (
    artifact_hash,
    manifest_hash,
    sign_artifact,
    sign_manifest,
    validate_provenance_configuration,
    verify_artifact_signature,
    verify_manifest_signature,
)
from src.reliability.service import DEFAULT_WINDOW_SIZE, build_slo_dashboard
from src.registry.store import STORE
from src.trust.scoring import compute_trust_score, record_usage_event as trust_record_usage_event
from src.versioning import compute_behavioral_diff
from src.discovery.index import LIVE_CAPABILITY_INDEX


@asynccontextmanager
async def _app_lifespan(_app: FastAPI):
    validate_auth_configuration()
    validate_federation_configuration()
    validate_provenance_configuration()
    yield


app = FastAPI(title="AgentHub Registry Service", version="0.1.0", lifespan=_app_lifespan)
app.include_router(system_router)
app.include_router(customer_router)
app.include_router(operator_router)


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


def _is_admin_owner(owner: str) -> bool:
    return owner in {"owner-dev", "owner-platform"}


def _require_invoice_read_access(owner: str, invoice: dict[str, Any]) -> None:
    invoice_owner = str(invoice.get("owner", ""))
    if _is_admin_owner(owner) or invoice_owner == owner:
        return
    raise HTTPException(status_code=403, detail="actor not permitted to view invoice")


def _require_contract_read_access(owner: str, contract: dict[str, Any]) -> None:
    buyer = str(contract.get("buyer", ""))
    seller = str(contract.get("seller", ""))
    if _is_admin_owner(owner) or owner in {buyer, seller}:
        return
    raise HTTPException(status_code=403, detail="actor not permitted to view contract")


def _delegate_policy_signals(delegate_agent_id: str) -> tuple[float | None, list[str]]:
    snapshot = LIVE_CAPABILITY_INDEX.snapshot()
    short_id = delegate_agent_id.split(":")[-1]
    rows = [row for row in snapshot["rows"] if row.agent_id in {delegate_agent_id, short_id}]
    if not rows:
        return None, []
    trust = max(float(row.trust_score) for row in rows)
    permissions = sorted({perm for row in rows for perm in row.permissions})
    return trust, permissions


def _constraints_from_filters(filters: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(filters, dict):
        return {}
    constraints: dict[str, Any] = {}
    for key in ("max_latency_ms", "max_cost_usd", "min_trust_score", "required_permissions", "allowed_protocols"):
        if key in filters and filters[key] is not None:
            constraints[key] = filters[key]
    return constraints


def _apply_pagination(rows: list[dict[str, Any]], pagination: dict[str, Any] | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
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


def _capability_search(
    *,
    query: str,
    filters: dict[str, Any] | None = None,
    pagination: dict[str, Any] | None = None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    constraints = _constraints_from_filters(filters)
    result = DISCOVERY_SERVICE.semantic_discovery(query=query, constraints=constraints, tenant_id=tenant_id)
    rows, page = _apply_pagination(list(result.get("data", [])), pagination)
    return {
        **result,
        "data": rows,
        "pagination": page,
    }


def _capability_match(
    *,
    input_required: list[str],
    output_required: list[str],
    compatibility_mode: str = "backward_compatible",
    filters: dict[str, Any] | None = None,
    pagination: dict[str, Any] | None = None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    constraints = _constraints_from_filters(filters)
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
    rows, page = _apply_pagination(rows, pagination)
    return {
        **result,
        "data": rows,
        "pagination": page,
    }


def _capability_recommend(
    *,
    task_description: str,
    current_capability_ids: list[str],
    filters: dict[str, Any] | None = None,
    pagination: dict[str, Any] | None = None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    constraints = _constraints_from_filters(filters)
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
    rows, page = _apply_pagination(rows, pagination)
    return {
        **result,
        "data": rows,
        "pagination": page,
    }


def _list_agent_capabilities(agent_id: str, tenant_id: str | None = None) -> dict[str, Any]:
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


def _resolve_tenant_id(raw_tenant_id: str | None) -> str:
    if raw_tenant_id is None:
        return "tenant-default"
    normalized = raw_tenant_id.strip()
    return normalized if normalized else "tenant-default"


def _append_warning_header(response: Response, warning: str) -> None:
    existing = response.headers.get("X-AgentHub-Deprecation-Warn")
    if existing:
        if warning not in existing:
            response.headers["X-AgentHub-Deprecation-Warn"] = f"{existing}; {warning}"
        return
    response.headers["X-AgentHub-Deprecation-Warn"] = warning


def _stable_error(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"detail": {"code": code, "message": message}})


def _meter_warn(
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


@app.middleware("http")
async def _agenthub_access_policy_middleware(request: Request, call_next):
    method = request.method.upper()
    path = request.url.path
    tenant_id = _resolve_tenant_id(request.headers.get("X-Tenant-ID"))
    classification = classify_route(method, path)
    mode = access_mode()

    auth_error: HTTPException | None = None
    owner: str | None = None
    try:
        owner = resolve_owner_from_headers(
            x_api_key=request.headers.get("X-API-Key"),
            authorization=request.headers.get("Authorization"),
            strict=False,
        )
    except HTTPException as exc:
        auth_error = exc

    request.state.agenthub_owner = owner
    request.state.agenthub_tenant_id = tenant_id

    violation = evaluate_access(classification=classification, owner=owner, tenant_id=tenant_id)
    if auth_error is not None and classification != "public" and owner is None:
        violation_code = "auth.invalid"
        violation_message = str(auth_error.detail)
    elif violation is not None:
        violation_code = violation.code
        violation_message = violation.message
    else:
        violation_code = None
        violation_message = None

    if violation_code is not None and mode == "enforce":
        status_code = 401 if violation_code in {"auth.required", "auth.invalid"} else 403
        return _stable_error(status_code, violation_code, violation_message or "request not permitted")

    response = await call_next(request)
    if violation_code is not None:
        warning = f"{violation_code}:{violation_message}"
        _append_warning_header(response, warning)
        _meter_warn(
            actor=owner or "anonymous",
            kind="access.warn",
            method=method,
            path=path,
            tenant_id=tenant_id,
            code=violation_code,
            message=violation_message or "request not permitted",
        )
    return response


@app.middleware("http")
async def _agenthub_idempotency_middleware(request: Request, call_next):
    method = request.method.upper()
    path = request.url.path
    if not requires_idempotency(method, path):
        return await call_next(request)

    mode = access_mode()
    tenant_id = _resolve_tenant_id(request.headers.get("X-Tenant-ID"))
    owner = getattr(request.state, "agenthub_owner", None)
    if owner is None:
        owner = resolve_owner_from_headers(
            x_api_key=request.headers.get("X-API-Key"),
            authorization=request.headers.get("Authorization"),
            strict=False,
        )
    actor = owner or "anonymous"

    key = request.headers.get("Idempotency-Key")
    if key is None or not key.strip():
        if mode == "enforce":
            return _stable_error(400, "idempotency.missing_key", "missing Idempotency-Key header")
        response = await call_next(request)
        _append_warning_header(response, "idempotency.missing_key:missing Idempotency-Key header")
        _meter_warn(
            actor=actor,
            kind="idempotency.warn",
            method=method,
            path=path,
            tenant_id=tenant_id,
            code="idempotency.missing_key",
            message="missing Idempotency-Key header",
        )
        return response

    key = key.strip()
    body = await request.body()
    hash_input = b"|".join([method.encode("utf-8"), path.encode("utf-8"), request.url.query.encode("utf-8"), body])
    request_hash = hashlib.sha256(hash_input).hexdigest()
    reservation = idempotency_storage.reserve(
        tenant_id=tenant_id,
        actor=actor,
        method=method,
        route=path,
        idempotency_key=key,
        request_hash=request_hash,
    )
    state = str(reservation.get("state", "reserved"))
    if state == "mismatch":
        return _stable_error(409, "idempotency.key_reused_with_different_payload", "idempotency key reuse with different payload")
    if state == "pending":
        return _stable_error(409, "idempotency.in_progress", "request with idempotency key is still in progress")
    if state == "response":
        replay = reservation["response"]
        replay_response = Response(
            content=replay["body"],
            status_code=int(replay.get("status_code", 200)),
            media_type=str(replay.get("content_type") or "application/json"),
        )
        for header_name, value in dict(replay.get("headers", {})).items():
            if header_name.lower() == "content-length":
                continue
            replay_response.headers[str(header_name)] = str(value)
        replay_response.headers["X-AgentHub-Idempotent-Replay"] = "true"
        return replay_response

    async def _receive() -> dict[str, Any]:
        return {"type": "http.request", "body": body, "more_body": False}

    request_with_body = Request(request.scope, _receive)
    try:
        response = await call_next(request_with_body)
        response_body = b""
        async for chunk in response.body_iterator:
            response_body += chunk
        content_type = response.headers.get("content-type", "application/json")
        response_headers = {k: v for k, v in response.headers.items()}

        if response.status_code >= 500:
            idempotency_storage.clear(
                tenant_id=tenant_id,
                actor=actor,
                method=method,
                route=path,
                idempotency_key=key,
            )
        else:
            idempotency_storage.finalize(
                tenant_id=tenant_id,
                actor=actor,
                method=method,
                route=path,
                idempotency_key=key,
                status_code=response.status_code,
                content_type=content_type,
                headers=response_headers,
                body=response_body,
            )

        final_response = Response(
            content=response_body,
            status_code=response.status_code,
            media_type=response.media_type,
            background=response.background,
        )
        for header_name, value in response_headers.items():
            if header_name.lower() == "content-length":
                continue
            final_response.headers[header_name] = value
        return final_response
    except Exception:
        idempotency_storage.clear(
            tenant_id=tenant_id,
            actor=actor,
            method=method,
            route=path,
            idempotency_key=key,
        )
        raise


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


@app.post("/v1/agents")
def register_agent(
    request: AgentRegistrationRequest,
    owner: str = Depends(require_api_key),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _resolve_tenant_id(x_tenant_id)

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

    return _serialize_agent(agent)


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
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _resolve_tenant_id(x_tenant_id)

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
    return response


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
def search_capabilities(
    request: SearchRequest,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _resolve_tenant_id(x_tenant_id)
    try:
        result = _capability_search(
            query=request.query,
            filters=request.filters.model_dump(exclude_none=True) if request.filters else None,
            pagination=request.pagination.model_dump(exclude_none=True) if request.pagination else None,
            tenant_id=tenant_id,
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
def match_capabilities(
    request: MatchRequest,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _resolve_tenant_id(x_tenant_id)
    try:
        result = _capability_match(
            input_required=_extract_required_fields(request.input_schema),
            output_required=_extract_required_fields(request.output_schema),
            compatibility_mode=request.filters.compatibility_mode if request.filters else "backward_compatible",
            filters=request.filters.model_dump(exclude_none=True) if request.filters else None,
            pagination=request.pagination.model_dump(exclude_none=True) if request.pagination else None,
            tenant_id=tenant_id,
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
def list_agent_capabilities(
    agent_id: str,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    return _list_agent_capabilities(agent_id, tenant_id=_resolve_tenant_id(x_tenant_id))


@app.post("/v1/capabilities/recommend")
def recommend_capabilities(
    request: RecommendRequest,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _resolve_tenant_id(x_tenant_id)
    try:
        result = _capability_recommend(
            task_description=request.task_description,
            current_capability_ids=request.current_capability_ids,
            filters=request.filters.model_dump(exclude_none=True) if request.filters else None,
            pagination=request.pagination.model_dump(exclude_none=True) if request.pagination else None,
            tenant_id=tenant_id,
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
def discovery_search(
    request: DiscoverySearchRequest,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    return DISCOVERY_SERVICE.semantic_discovery(
        query=request.query,
        constraints=request.constraints or {},
        tenant_id=_resolve_tenant_id(x_tenant_id),
    )


@app.post("/v1/discovery/contract-match")
def discovery_contract_match(
    request: ContractMatchRequest,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    constraints = request.constraints or {}
    return DISCOVERY_SERVICE.contract_match(
        input_required=[str(x) for x in request.input_schema.get("required", [])],
        output_required=[str(x) for x in request.output_schema.get("required", [])],
        max_cost_usd=constraints.get("max_cost_usd"),
        tenant_id=_resolve_tenant_id(x_tenant_id),
    )


@app.post("/v1/discovery/compatibility")
def discovery_compatibility(
    request: CompatibilityRequest,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    return DISCOVERY_SERVICE.compatibility_report(
        my_schema=request.my_schema,
        agent_id=request.agent_id,
        tenant_id=_resolve_tenant_id(x_tenant_id),
    )


@app.get("/v1/discovery/mcp-tools")
def discovery_mcp_tools() -> dict[str, Any]:
    return {"tools": mcp_tool_declarations()}


@app.get("/v1/discovery/agent-manifest")
def discovery_agent_manifest(
    agent_id: str,
    version: str | None = None,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _resolve_tenant_id(x_tenant_id)
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
    _ = require_operator_role(owner, x_operator_role, {"admin"})
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
    _ = require_operator_role(owner, x_operator_role, {"admin"})
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
def get_billing_invoice(invoice_id: str, owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        invoice = get_invoice(invoice_id)
        _require_invoice_read_access(owner, invoice)
        return invoice
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="invoice not found") from exc


@app.post("/v1/billing/invoices/{invoice_id}/reconcile")
def post_billing_reconcile(invoice_id: str, owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        invoice = get_invoice(invoice_id)
        _require_invoice_read_access(owner, invoice)
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


@app.get("/v1/compliance/controls")
def get_compliance_controls(
    framework: str | None = Query(default=None, min_length=3),
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return {"data": list_compliance_controls(framework=framework)}


@app.post("/v1/compliance/evidence/export")
def post_compliance_evidence_export(
    request: ComplianceEvidenceExportRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if owner not in {"owner-dev", "owner-platform"}:
        raise HTTPException(status_code=403, detail="compliance evidence export requires admin role")
    try:
        report = export_evidence_pack(actor=owner, framework=request.framework, control_ids=request.control_ids)
        record_metering_event(
            actor=owner,
            operation="compliance.evidence.export",
            cost_usd=0.0,
            metadata={"framework": request.framework, "report_id": report["report_id"]},
        )
        return report
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/compliance/evidence")
def get_compliance_evidence_reports(
    framework: str | None = Query(default=None, min_length=3),
    limit: int = Query(default=20, ge=1, le=500),
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if owner not in {"owner-dev", "owner-platform"}:
        raise HTTPException(status_code=403, detail="compliance evidence listing requires admin role")
    return {"data": list_evidence_reports(framework=framework, limit=limit)}


@app.post("/v1/procurement/policy-packs")
def post_procurement_policy_pack(
    request: ProcurementPolicyPackUpsertRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        row = upsert_policy_pack(
            actor=owner,
            buyer=request.buyer,
            auto_approve_limit_usd=request.auto_approve_limit_usd,
            hard_stop_limit_usd=request.hard_stop_limit_usd,
            allowed_sellers=request.allowed_sellers,
        )
        record_metering_event(
            actor=owner,
            operation="procurement.policy_pack.upsert",
            cost_usd=0.0,
            metadata={"buyer": request.buyer, "pack_id": row["pack_id"]},
        )
        return row
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/procurement/policy-packs")
def get_procurement_policy_packs(
    buyer: str | None = Query(default=None, min_length=3),
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if owner not in {"owner-dev", "owner-platform"}:
        if buyer is None:
            buyer = owner
        elif buyer != owner:
            raise HTTPException(status_code=403, detail="actor not permitted to view other buyer policy packs")
    return {"data": list_policy_packs(buyer=buyer)}


@app.post("/v1/procurement/approvals")
def post_procurement_approval_request(
    request: ProcurementApprovalCreateRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        row = create_approval_request(
            actor=owner,
            buyer=request.buyer,
            listing_id=request.listing_id,
            units=request.units,
            estimated_total_usd=request.estimated_total_usd,
            note=request.note,
        )
        record_metering_event(
            actor=owner,
            operation="procurement.approval.request",
            cost_usd=0.0,
            metadata={"buyer": request.buyer, "approval_id": row["approval_id"]},
        )
        return row
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/procurement/approvals")
def get_procurement_approvals(
    buyer: str | None = Query(default=None, min_length=3),
    status: str | None = Query(default=None, min_length=3),
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if owner not in {"owner-dev", "owner-platform"}:
        if buyer is None:
            buyer = owner
        elif buyer != owner:
            raise HTTPException(status_code=403, detail="actor not permitted to view other buyer approvals")
    return {"data": list_approvals(buyer=buyer, status=status)}


@app.post("/v1/procurement/approvals/{approval_id}/decision")
def post_procurement_approval_decision(
    approval_id: str,
    request: ProcurementApprovalDecisionRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        row = decide_approval(
            actor=owner,
            approval_id=approval_id,
            decision=request.decision,
            approved_max_total_usd=request.approved_max_total_usd,
            note=request.note,
        )
        record_metering_event(
            actor=owner,
            operation="procurement.approval.decision",
            cost_usd=0.0,
            metadata={"approval_id": approval_id, "decision": request.decision},
        )
        return row
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="approval not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/procurement/exceptions")
def post_procurement_exception(
    request: ProcurementExceptionCreateRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        row = create_exception(
            actor=owner,
            buyer=request.buyer,
            reason=request.reason,
            override_hard_stop_limit_usd=request.override_hard_stop_limit_usd,
            allow_seller_id=request.allow_seller_id,
            expires_at=request.expires_at,
        )
        record_metering_event(
            actor=owner,
            operation="procurement.exception.create",
            cost_usd=0.0,
            metadata={"exception_id": row["exception_id"], "buyer": request.buyer},
        )
        return row
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/procurement/exceptions")
def get_procurement_exceptions(
    buyer: str | None = Query(default=None, min_length=3),
    active_only: bool = Query(default=False),
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if owner not in {"owner-dev", "owner-platform"}:
        if buyer is None:
            buyer = owner
        elif buyer != owner:
            raise HTTPException(status_code=403, detail="actor not permitted to view other buyer exceptions")
    return {"data": list_exceptions(buyer=buyer, active_only=active_only)}


@app.get("/v1/procurement/audit")
def get_procurement_audit(
    buyer: str | None = Query(default=None, min_length=3),
    limit: int = Query(default=100, ge=1, le=500),
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if owner not in {"owner-dev", "owner-platform"}:
        if buyer is None:
            buyer = owner
        elif buyer != owner:
            raise HTTPException(status_code=403, detail="actor not permitted to view other buyer audit trail")
    return {"data": list_procurement_audit_events(buyer=buyer, limit=limit)}


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
            procurement_approval_id=request.procurement_approval_id,
            procurement_exception_id=request.procurement_exception_id,
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
def get_marketplace_contract(contract_id: str, owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        contract = get_contract(contract_id)
        _require_contract_read_access(owner, contract)
        return contract
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


@app.post("/v1/marketplace/contracts/{contract_id}/disputes")
def post_marketplace_dispute(
    contract_id: str,
    request: MarketplaceDisputeCreateRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        row = create_dispute(
            contract_id=contract_id,
            actor=owner,
            reason=request.reason,
            requested_amount_usd=request.requested_amount_usd,
        )
        record_metering_event(actor=owner, operation="marketplace.dispute.create", cost_usd=0.0, metadata={"contract_id": contract_id})
        return row
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="contract not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/marketplace/contracts/{contract_id}/disputes")
def get_marketplace_disputes(contract_id: str, owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        contract = get_contract(contract_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="contract not found") from exc
    _require_contract_read_access(owner, contract)
    return {"data": list_disputes(contract_id=contract_id)}


@app.post("/v1/marketplace/disputes/{dispute_id}/resolve")
def post_marketplace_dispute_resolve(
    dispute_id: str,
    request: MarketplaceDisputeResolveRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        row = resolve_dispute(
            dispute_id=dispute_id,
            actor=owner,
            resolution=request.resolution,
            approved_amount_usd=request.approved_amount_usd,
        )
        record_metering_event(actor=owner, operation="marketplace.dispute.resolve", cost_usd=0.0, metadata={"dispute_id": dispute_id})
        return row
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="dispute not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/marketplace/contracts/{contract_id}/payout")
def post_marketplace_payout(contract_id: str, owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        row = create_payout(contract_id=contract_id, actor=owner)
        record_metering_event(actor=owner, operation="marketplace.payout", cost_usd=0.0, metadata={"contract_id": contract_id})
        return row
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="contract not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/marketplace/contracts/{contract_id}/payouts")
def get_marketplace_payouts(contract_id: str, owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        contract = get_contract(contract_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="contract not found") from exc
    _require_contract_read_access(owner, contract)
    return {"data": list_payouts(contract_id=contract_id)}


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
        raise HTTPException(
            status_code=409,
            detail={
                "code": "idempotency.key_reused_with_different_payload",
                "message": "idempotency key replay with different request payload",
            },
        )
    if reservation_state == "response":
        return copy.deepcopy(reservation["response"])
    if reservation_state == "pending":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "idempotency.in_progress",
                "message": "idempotency key request already in progress",
            },
        )

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
            requested_residency_region=request.requested_residency_region,
            connection_mode=request.connection_mode,
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


@app.get("/v1/federation/domains")
def get_federation_domains(_owner: str = Depends(require_api_key)) -> dict[str, Any]:
    return {"data": list_domain_profiles()}


@app.get("/v1/federation/audit")
def get_federation_audit(limit: int = Query(default=50, ge=1, le=500), _owner: str = Depends(require_api_key)) -> dict[str, Any]:
    return {"data": list_federation_audit(limit=limit)}


@app.get("/v1/federation/attestations/export")
def get_federation_attestation_export(
    domain_id: str | None = Query(default=None, min_length=3),
    limit: int = Query(default=250, ge=1, le=1000),
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if owner not in {"owner-dev", "owner-platform"}:
        raise HTTPException(status_code=403, detail="federation compliance export requires admin role")
    return export_attestation_bundle(actor=owner, domain_id=domain_id, limit=limit)


@app.get("/v1/delegations/{delegation_id}/status")
def get_delegation_status_endpoint(delegation_id: str) -> dict[str, Any]:
    row = get_delegation_status(delegation_id)
    if not row:
        raise HTTPException(status_code=404, detail="delegation not found")
    return row


@app.get("/v1/agents/{agent_id}/trust")
def get_agent_trust(
    agent_id: str,
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _resolve_tenant_id(x_tenant_id)
    try:
        agent = STORE.get_agent(agent_id, tenant_id=tenant_id)
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
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _resolve_tenant_id(x_tenant_id)

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

    return _serialize_agent(agent)


@app.delete("/v1/agents/{agent_id}")
def delete_agent(
    agent_id: str,
    owner: str = Depends(require_api_key),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> dict[str, Any]:
    tenant_id = _resolve_tenant_id(x_tenant_id)

    try:
        agent = STORE.delete_agent(agent_id, owner, tenant_id=tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="agent not found") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    return {"id": agent.agent_id, "status": agent.status}
