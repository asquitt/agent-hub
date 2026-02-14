"""Policy simulation — what-if analysis for access control changes.

Enables:
- Simulate adding/removing roles, scopes, group memberships
- Batch evaluation of policy effects under hypothetical changes
- Impact analysis: which agents would be affected by a rule change
- Diff comparison between current and proposed policy states
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from src.policy.policy_as_code import evaluate as policy_evaluate, _rules

_log = logging.getLogger("agenthub.policy_sim")

# In-memory simulation store (capped)
_MAX_SIMULATIONS = 10_000
_simulations: dict[str, dict[str, Any]] = {}


def simulate_access(
    *,
    agent_id: str,
    actions: list[str],
    resource: str | None = None,
    context_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Simulate policy evaluation for multiple actions.

    Runs each action through the policy engine in dry_run mode
    with optional context overrides (e.g., hypothetical role changes).
    """
    results: list[dict[str, Any]] = []
    for action in actions:
        ctx = dict(context_overrides or {})
        result = policy_evaluate(
            agent_id=agent_id,
            action=action,
            resource=resource,
            context=ctx,
            dry_run=True,
        )
        results.append({
            "action": action,
            "decision": result["decision"],
            "matched_rules": result["matched_rules"],
            "total_rules_evaluated": result["total_rules_evaluated"],
        })

    allowed = sum(1 for r in results if r["decision"] == "allow")
    denied = sum(1 for r in results if r["decision"] == "deny")
    requires_approval = sum(1 for r in results if r["decision"] == "require_approval")

    return {
        "agent_id": agent_id,
        "resource": resource,
        "context_overrides": context_overrides or {},
        "results": results,
        "summary": {
            "total": len(results),
            "allowed": allowed,
            "denied": denied,
            "requires_approval": requires_approval,
        },
        "timestamp": time.time(),
    }


def simulate_rule_change(
    *,
    rule_changes: list[dict[str, Any]],
    test_cases: list[dict[str, Any]],
) -> dict[str, Any]:
    """Simulate the impact of adding/modifying/disabling rules.

    rule_changes: list of {action: "add"|"modify"|"disable", rule: {...}}
    test_cases: list of {agent_id, action, resource, context} to evaluate

    Returns before/after comparison for each test case.
    """
    sim_id = f"sim-{uuid.uuid4().hex[:12]}"

    # Snapshot current rules
    original_rules = {rid: dict(r) for rid, r in _rules.items()}

    # Evaluate BEFORE state
    before_results: list[dict[str, Any]] = []
    for tc in test_cases:
        result = policy_evaluate(
            agent_id=tc.get("agent_id", ""),
            action=tc.get("action", ""),
            resource=tc.get("resource"),
            context=tc.get("context"),
            dry_run=True,
        )
        before_results.append({
            "agent_id": tc.get("agent_id", ""),
            "action": tc.get("action", ""),
            "resource": tc.get("resource"),
            "decision": result["decision"],
            "matched_rules": result["matched_rules"],
        })

    # Apply hypothetical changes
    applied_changes: list[dict[str, Any]] = []
    for change in rule_changes:
        change_action = change.get("action", "")
        rule_data = change.get("rule", {})
        rule_id = rule_data.get("rule_id", "")

        if change_action == "add":
            temp_id = rule_id or f"sim-rule-{uuid.uuid4().hex[:8]}"
            _rules[temp_id] = {
                "rule_id": temp_id,
                "name": rule_data.get("name", "simulated rule"),
                "description": rule_data.get("description", ""),
                "effect": rule_data.get("effect", "deny"),
                "priority": rule_data.get("priority", 100),
                "conditions": rule_data.get("conditions", []),
                "target_agents": rule_data.get("target_agents"),
                "target_actions": rule_data.get("target_actions"),
                "target_resources": rule_data.get("target_resources"),
                "enabled": True,
                "created_at": time.time(),
                "version": 1,
            }
            applied_changes.append({"action": "add", "rule_id": temp_id})
        elif change_action == "modify" and rule_id in _rules:
            for key, value in rule_data.items():
                if key != "rule_id":
                    _rules[rule_id][key] = value
            applied_changes.append({"action": "modify", "rule_id": rule_id})
        elif change_action == "disable" and rule_id in _rules:
            _rules[rule_id]["enabled"] = False
            applied_changes.append({"action": "disable", "rule_id": rule_id})

    # Evaluate AFTER state
    after_results: list[dict[str, Any]] = []
    for tc in test_cases:
        result = policy_evaluate(
            agent_id=tc.get("agent_id", ""),
            action=tc.get("action", ""),
            resource=tc.get("resource"),
            context=tc.get("context"),
            dry_run=True,
        )
        after_results.append({
            "agent_id": tc.get("agent_id", ""),
            "action": tc.get("action", ""),
            "resource": tc.get("resource"),
            "decision": result["decision"],
            "matched_rules": result["matched_rules"],
        })

    # Restore original rules
    _rules.clear()
    _rules.update(original_rules)

    # Compute diff
    changed_decisions: list[dict[str, Any]] = []
    for i, (before, after) in enumerate(zip(before_results, after_results)):
        if before["decision"] != after["decision"]:
            changed_decisions.append({
                "test_case_index": i,
                "agent_id": before["agent_id"],
                "action": before["action"],
                "resource": before.get("resource"),
                "before": before["decision"],
                "after": after["decision"],
            })

    simulation: dict[str, Any] = {
        "simulation_id": sim_id,
        "rule_changes": applied_changes,
        "test_cases_count": len(test_cases),
        "before_results": before_results,
        "after_results": after_results,
        "changed_decisions": changed_decisions,
        "impact_summary": {
            "total_test_cases": len(test_cases),
            "decisions_changed": len(changed_decisions),
            "no_change": len(test_cases) - len(changed_decisions),
        },
        "timestamp": time.time(),
    }

    # Store simulation
    if len(_simulations) >= _MAX_SIMULATIONS:
        oldest = min(_simulations, key=lambda k: _simulations[k].get("timestamp", 0))
        del _simulations[oldest]
    _simulations[sim_id] = simulation

    return simulation


def impact_analysis(
    *,
    agent_ids: list[str],
    action: str,
    resource: str | None = None,
) -> dict[str, Any]:
    """Evaluate current policy against multiple agents to see who's allowed/denied.

    Useful for: "If I enforce this action on this resource, who gets blocked?"
    """
    results: list[dict[str, Any]] = []
    for agent_id in agent_ids:
        result = policy_evaluate(
            agent_id=agent_id,
            action=action,
            resource=resource,
            dry_run=True,
        )
        results.append({
            "agent_id": agent_id,
            "decision": result["decision"],
            "matched_rules": result["matched_rules"],
        })

    allowed = [r for r in results if r["decision"] == "allow"]
    denied = [r for r in results if r["decision"] == "deny"]
    requires_approval = [r for r in results if r["decision"] == "require_approval"]

    return {
        "action": action,
        "resource": resource,
        "total_agents": len(agent_ids),
        "results": results,
        "summary": {
            "allowed": len(allowed),
            "denied": len(denied),
            "requires_approval": len(requires_approval),
        },
    }


def get_simulation(simulation_id: str) -> dict[str, Any]:
    """Retrieve a stored simulation result."""
    sim = _simulations.get(simulation_id)
    if sim is None:
        raise KeyError(f"simulation not found: {simulation_id}")
    return sim


def list_simulations(limit: int = 50) -> list[dict[str, Any]]:
    """List recent simulations."""
    sims = sorted(_simulations.values(), key=lambda s: s.get("timestamp", 0), reverse=True)
    results: list[dict[str, Any]] = []
    for sim in sims[:limit]:
        results.append({
            "simulation_id": sim["simulation_id"],
            "test_cases_count": sim["test_cases_count"],
            "decisions_changed": sim["impact_summary"]["decisions_changed"],
            "timestamp": sim["timestamp"],
        })
    return results


def _reset() -> None:
    """Reset state for testing."""
    _simulations.clear()
