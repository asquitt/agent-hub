"""Cost metering, reliability SLO dashboard, devhub, adversarial testing, threat intel routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

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
from src.trust.threat_intel import (
    add_indicator,
    check_indicator,
    get_agent_threat_assessment,
    get_match_history,
    get_threat_summary,
    list_indicators,
    register_feed,
    list_feeds,
)
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


# ── Threat Intelligence ───────────────────────────────────────────


class AddIndicatorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    indicator_type: str = Field(min_length=1, max_length=64)
    value: str = Field(min_length=1, max_length=512)
    severity: str = Field(default="medium", max_length=16)
    description: str = Field(default="", max_length=1024)
    source_feed: str | None = Field(default=None, max_length=256)
    ttl_seconds: int = Field(default=2592000, ge=3600, le=31536000)
    tags: list[str] | None = None


class CheckIndicatorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    indicator_type: str = Field(min_length=1, max_length=64)
    value: str = Field(min_length=1, max_length=512)
    agent_id: str | None = Field(default=None, max_length=256)
    context: str = Field(default="", max_length=512)


class RegisterFeedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    feed_name: str = Field(min_length=1, max_length=256)
    feed_url: str = Field(default="", max_length=1024)
    feed_type: str = Field(default="stix-taxii", max_length=64)
    description: str = Field(default="", max_length=1024)


@router.post("/v1/threat-intel/indicators")
def post_add_indicator(
    request: AddIndicatorRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Add a threat indicator (IOC)."""
    try:
        return add_indicator(
            indicator_type=request.indicator_type,
            value=request.value,
            severity=request.severity,
            description=request.description,
            source_feed=request.source_feed,
            ttl_seconds=request.ttl_seconds,
            tags=request.tags,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/threat-intel/indicators")
def get_indicators(
    indicator_type: str | None = None,
    severity: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List threat indicators."""
    indicators = list_indicators(indicator_type=indicator_type, severity=severity, limit=limit)
    return {"count": len(indicators), "indicators": indicators}


@router.post("/v1/threat-intel/check")
def post_check_indicator(
    request: CheckIndicatorRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Check a value against threat indicators."""
    return check_indicator(
        indicator_type=request.indicator_type,
        value=request.value,
        agent_id=request.agent_id,
        context=request.context,
    )


@router.get("/v1/threat-intel/agents/{agent_id}/assessment")
def get_threat_assessment(
    agent_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get threat assessment for an agent."""
    return get_agent_threat_assessment(agent_id)


@router.post("/v1/threat-intel/feeds")
def post_register_feed(
    request: RegisterFeedRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Register a threat intelligence feed."""
    return register_feed(
        feed_name=request.feed_name,
        feed_url=request.feed_url,
        feed_type=request.feed_type,
        description=request.description,
    )


@router.get("/v1/threat-intel/feeds")
def get_feeds(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """List registered threat intelligence feeds."""
    feeds = list_feeds()
    return {"count": len(feeds), "feeds": feeds}


@router.get("/v1/threat-intel/matches")
def get_matches(
    agent_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get threat match history."""
    matches = get_match_history(agent_id=agent_id, limit=limit)
    return {"count": len(matches), "matches": matches}


@router.get("/v1/threat-intel/summary")
def get_intel_summary(
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get threat intelligence summary."""
    return get_threat_summary()
