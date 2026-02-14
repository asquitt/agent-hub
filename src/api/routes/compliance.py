"""Compliance controls, evidence export, evidence listing routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.auth import require_api_key
from src.api.models import ComplianceEvidenceExportRequest
from src.compliance import export_evidence_pack, list_controls as list_compliance_controls, list_evidence_reports
from pydantic import BaseModel, ConfigDict, Field
from src.compliance.dashboard import get_dashboard
from src.compliance.owasp_agentic import get_gap_analysis, get_owasp_mapping
from src.policy.decision_graph import (
    build_decision_graph,
    get_decision,
    get_decision_chain,
    get_decision_statistics,
    get_decisions_for_agent,
    record_decision,
)
from src.compliance.soc2_evidence import (
    collect_evidence_for_criteria,
    generate_evidence_package,
    get_compliance_summary,
    record_evidence,
    verify_evidence_integrity,
)
from src.cost_governance.service import record_metering_event

router = APIRouter(tags=["compliance"])


@router.get("/v1/compliance/controls")
def get_compliance_controls(
    framework: str | None = Query(default=None, min_length=3),
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return {"data": list_compliance_controls(framework=framework)}


@router.post("/v1/compliance/evidence/export")
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


@router.get("/v1/compliance/evidence")
def get_compliance_evidence_reports(
    framework: str | None = Query(default=None, min_length=3),
    limit: int = Query(default=20, ge=1, le=500),
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if owner not in {"owner-dev", "owner-platform"}:
        raise HTTPException(status_code=403, detail="compliance evidence listing requires admin role")
    return {"data": list_evidence_reports(framework=framework, limit=limit)}


@router.get("/v1/compliance/owasp-agentic")
def get_owasp_agentic_mapping(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get the OWASP Agentic Top 10 control mapping."""
    return get_owasp_mapping()


@router.get("/v1/compliance/owasp-agentic/gaps")
def get_owasp_agentic_gaps(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get OWASP Agentic Top 10 gap analysis."""
    return get_gap_analysis()


# ── SOC2 Evidence Automation ────────────────────────────────────────


class RecordEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    criteria: str = Field(min_length=2, max_length=10)
    evidence_type: str = Field(min_length=1, max_length=64)
    description: str = Field(min_length=1, max_length=512)
    actor: str = Field(min_length=1, max_length=256)
    details: dict[str, Any] | None = None
    agent_id: str | None = Field(default=None, max_length=256)


class GeneratePackageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    criteria: list[str] | None = None
    start_time: float | None = None
    end_time: float | None = None
    auditor_name: str = Field(default="", max_length=256)


@router.post("/v1/compliance/soc2/evidence")
def post_record_evidence(
    request: RecordEvidenceRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Record a SOC2 evidence item."""
    try:
        return record_evidence(
            criteria=request.criteria,
            evidence_type=request.evidence_type,
            description=request.description,
            actor=request.actor,
            details=request.details,
            agent_id=request.agent_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/compliance/soc2/evidence/{criteria}")
def get_evidence_by_criteria(
    criteria: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get all evidence for a SOC2 criteria."""
    try:
        items = collect_evidence_for_criteria(criteria)
        return {"criteria": criteria, "count": len(items), "evidence": items}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/v1/compliance/soc2/evidence-package")
def post_generate_evidence_package(
    request: GeneratePackageRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Generate a structured evidence package for auditor review."""
    try:
        return generate_evidence_package(
            criteria=request.criteria,
            start_time=request.start_time,
            end_time=request.end_time,
            auditor_name=request.auditor_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/compliance/soc2/summary")
def get_soc2_summary(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get SOC2 compliance evidence summary."""
    return get_compliance_summary()


@router.get("/v1/compliance/soc2/evidence/{evidence_id}/verify")
def get_verify_evidence(
    evidence_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Verify integrity of a specific evidence record."""
    try:
        return verify_evidence_integrity(evidence_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ── Compliance Dashboard ────────────────────────────────────────────


@router.get("/v1/compliance/dashboard")
def get_compliance_dashboard(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get the unified compliance dashboard with overall posture score."""
    return get_dashboard()


# ── Policy Decision Graph ───────────────────────────────────────────


class RecordDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str | None = Field(default=None, max_length=256)
    agent_id: str = Field(min_length=1, max_length=256)
    action: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=512)
    decision: str = Field(pattern="^(allow|deny)$")
    reason: str = Field(min_length=1, max_length=512)
    policies_evaluated: list[str] | None = None
    conditions_checked: list[dict[str, Any]] | None = None
    parent_decision_id: str | None = None
    delegation_chain: list[str] | None = None
    latency_ms: float = 0.0


@router.post("/v1/policy/decisions")
def post_record_decision(
    request: RecordDecisionRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Record a policy decision."""
    return record_decision(
        request_id=request.request_id,
        agent_id=request.agent_id,
        action=request.action,
        resource=request.resource,
        decision=request.decision,
        reason=request.reason,
        policies_evaluated=request.policies_evaluated,
        conditions_checked=request.conditions_checked,
        parent_decision_id=request.parent_decision_id,
        delegation_chain=request.delegation_chain,
        latency_ms=request.latency_ms,
    )


@router.get("/v1/policy/decisions/{decision_id}")
def get_policy_decision(
    decision_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get a specific policy decision."""
    try:
        return get_decision(decision_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/v1/policy/decisions/{decision_id}/chain")
def get_policy_decision_chain(
    decision_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Trace the full decision chain from a decision back to root."""
    chain = get_decision_chain(decision_id)
    return {"decision_id": decision_id, "chain_length": len(chain), "chain": chain}


@router.get("/v1/policy/agents/{agent_id}/decisions")
def get_agent_decisions(
    agent_id: str,
    action: str | None = None,
    decision_filter: str | None = Query(default=None, alias="decision"),
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get recent policy decisions for an agent."""
    decisions = get_decisions_for_agent(agent_id, action=action, decision_filter=decision_filter)
    return {"agent_id": agent_id, "count": len(decisions), "decisions": decisions}


@router.get("/v1/policy/decisions-stats")
def get_policy_decision_stats(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get aggregate statistics on policy decisions."""
    return get_decision_statistics()


@router.get("/v1/policy/requests/{request_id}/graph")
def get_request_decision_graph(
    request_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Build the decision graph for a specific request."""
    return build_decision_graph(request_id)
