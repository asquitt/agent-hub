"""Cost metering, reliability SLO dashboard, devhub, adversarial testing routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from src.api.auth import require_api_key
from src.api.models import DevHubReviewCreateRequest, DevHubReviewDecisionRequest
from src.api.operator_helpers import require_operator_role
from src.cost_governance.service import list_metering_events
from src.devhub import service as devhub_service
from src.eval.adversarial import (
    get_payload_catalog,
    get_test_run,
    list_test_runs,
    run_full_adversarial_suite,
    run_prompt_injection_tests,
    run_scope_escalation_tests,
)
from src.registry.store import STORE
from src.reliability.service import DEFAULT_WINDOW_SIZE, build_slo_dashboard

router = APIRouter(tags=["misc"])


@router.get("/v1/cost/metering")
def get_cost_metering_endpoint(limit: int = Query(default=50, ge=1, le=500), _owner: str = Depends(require_api_key)) -> dict[str, Any]:
    return {"data": list_metering_events(limit=limit)}


@router.get("/v1/reliability/slo-dashboard")
def get_reliability_slo_dashboard(
    window_size: int = Query(default=50, ge=1, le=1000),
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return build_slo_dashboard(window_size=window_size)


@router.post("/v1/devhub/reviews")
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


@router.get("/v1/devhub/reviews")
def list_devhub_reviews(
    agent_id: str | None = Query(default=None),
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return {"data": devhub_service.list_release_reviews(agent_id=agent_id)}


@router.get("/v1/devhub/reviews/{review_id}")
def get_devhub_review(review_id: str, _owner: str = Depends(require_api_key)) -> dict[str, Any]:
    try:
        return devhub_service.get_release_review(review_id=review_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="review not found") from exc


@router.post("/v1/devhub/reviews/{review_id}/decision")
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


@router.post("/v1/devhub/reviews/{review_id}/promote")
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


@router.get("/v1/devhub/promotions")
def get_devhub_promotions(
    agent_id: str | None = Query(default=None),
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return {"data": devhub_service.list_promotions(agent_id=agent_id)}


# ── Adversarial Testing ───────────────────────────────────────────


@router.post("/v1/eval/adversarial/run")
def post_run_adversarial_suite(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Run the full adversarial test suite."""
    return run_full_adversarial_suite()


@router.post("/v1/eval/adversarial/prompt-injection")
def post_run_prompt_injection(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Run prompt injection tests only."""
    return run_prompt_injection_tests()


@router.post("/v1/eval/adversarial/scope-escalation")
def post_run_scope_escalation(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Run scope escalation tests only."""
    return run_scope_escalation_tests()


@router.get("/v1/eval/adversarial/runs")
def get_adversarial_runs(
    limit: int = Query(default=20, ge=1, le=100),
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List recent adversarial test runs."""
    runs = list_test_runs(limit=limit)
    return {"count": len(runs), "runs": runs}


@router.get("/v1/eval/adversarial/runs/{run_id}")
def get_adversarial_run(
    run_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get a specific adversarial test run."""
    try:
        return get_test_run(run_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/v1/eval/adversarial/payloads")
def get_adversarial_payloads(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get the adversarial payload catalog."""
    return get_payload_catalog()
