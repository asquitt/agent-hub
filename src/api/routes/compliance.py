"""Compliance controls, evidence export, evidence listing routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.auth import require_api_key
from src.api.models import ComplianceEvidenceExportRequest
from src.compliance import export_evidence_pack, list_controls as list_compliance_controls, list_evidence_reports
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
