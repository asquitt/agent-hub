"""Policy simulation routes — what-if analysis for access control."""
from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException

from src.runtime.policy_sim import (
    get_simulation,
    impact_analysis,
    list_simulations,
    simulate_access,
    simulate_rule_change,
)

router = APIRouter(prefix="/v1/policy-sim", tags=["policy-sim"])


@router.post("/access")
def sim_access(body: dict, x_api_key: str = Header(...)):
    """Simulate policy evaluation for an agent across multiple actions."""
    agent_id = body.get("agent_id", "")
    actions = body.get("actions", [])
    if not agent_id or not actions:
        raise HTTPException(status_code=422, detail="agent_id and actions required")
    result = simulate_access(
        agent_id=agent_id,
        actions=actions,
        resource=body.get("resource"),
        context_overrides=body.get("context_overrides"),
    )
    return result


@router.post("/rule-change")
def sim_rule_change(body: dict, x_api_key: str = Header(...)):
    """Simulate the impact of adding/modifying/disabling policy rules."""
    rule_changes = body.get("rule_changes", [])
    test_cases = body.get("test_cases", [])
    if not rule_changes or not test_cases:
        raise HTTPException(status_code=422, detail="rule_changes and test_cases required")
    result = simulate_rule_change(
        rule_changes=rule_changes,
        test_cases=test_cases,
    )
    return result


@router.post("/impact")
def sim_impact(body: dict, x_api_key: str = Header(...)):
    """Run impact analysis: evaluate policy across multiple agents."""
    agent_ids = body.get("agent_ids", [])
    action = body.get("action", "")
    if not agent_ids or not action:
        raise HTTPException(status_code=422, detail="agent_ids and action required")
    result = impact_analysis(
        agent_ids=agent_ids,
        action=action,
        resource=body.get("resource"),
    )
    return result


@router.get("/simulations")
def get_simulations(
    limit: int = 50,
    x_api_key: str = Header(...),
):
    """List recent policy simulations."""
    sims = list_simulations(limit=limit)
    return {"simulations": sims, "count": len(sims)}


@router.get("/simulations/{simulation_id}")
def get_simulation_detail(simulation_id: str, x_api_key: str = Header(...)):
    """Retrieve a specific simulation result."""
    try:
        sim = get_simulation(simulation_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return sim
