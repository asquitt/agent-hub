"""Policy-as-Code Engine — declarative rules for agent access control.

Enables:
- Declarative policy rules with conditions, effects, and targets
- Policy versioning and rollback
- Dry-run evaluation mode
- Rule priority and conflict resolution
- Condition expressions: attribute matching, time windows, risk thresholds
"""
from __future__ import annotations

import logging
import re
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.policy_as_code")

# Effects
EFFECT_ALLOW = "allow"
EFFECT_DENY = "deny"
EFFECT_REQUIRE_APPROVAL = "require_approval"

VALID_EFFECTS = {EFFECT_ALLOW, EFFECT_DENY, EFFECT_REQUIRE_APPROVAL}

# Condition operators
OP_EQUALS = "equals"
OP_NOT_EQUALS = "not_equals"
OP_IN = "in"
OP_NOT_IN = "not_in"
OP_MATCHES = "matches"  # regex
OP_GREATER_THAN = "greater_than"
OP_LESS_THAN = "less_than"

VALID_OPERATORS = {OP_EQUALS, OP_NOT_EQUALS, OP_IN, OP_NOT_IN, OP_MATCHES, OP_GREATER_THAN, OP_LESS_THAN}

# In-memory stores
_MAX_RECORDS = 10_000
_rules: dict[str, dict[str, Any]] = {}  # rule_id -> rule
_rule_versions: list[dict[str, Any]] = []  # version history
_evaluations: list[dict[str, Any]] = []  # evaluation log


def create_rule(
    *,
    name: str,
    description: str = "",
    effect: str,
    priority: int = 100,
    conditions: list[dict[str, Any]] | None = None,
    target_agents: list[str] | None = None,
    target_actions: list[str] | None = None,
    target_resources: list[str] | None = None,
    enabled: bool = True,
) -> dict[str, Any]:
    """Create a policy rule."""
    if effect not in VALID_EFFECTS:
        raise ValueError(f"invalid effect: {effect}")
    if priority < 0 or priority > 1000:
        raise ValueError("priority must be 0-1000")

    # Validate conditions
    parsed_conditions = _parse_conditions(conditions or [])

    rule_id = f"rule-{uuid.uuid4().hex[:12]}"
    now = time.time()

    rule: dict[str, Any] = {
        "rule_id": rule_id,
        "name": name,
        "description": description,
        "effect": effect,
        "priority": priority,
        "conditions": parsed_conditions,
        "target_agents": target_agents,
        "target_actions": target_actions,
        "target_resources": target_resources,
        "enabled": enabled,
        "version": 1,
        "created_at": now,
        "updated_at": now,
    }

    _rules[rule_id] = rule
    _record_version(rule, "created")

    if len(_rules) > _MAX_RECORDS:
        oldest = sorted(_rules, key=lambda k: _rules[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _rules[k]

    _log.info("rule created: id=%s name=%s effect=%s", rule_id, name, effect)
    return rule


def update_rule(
    rule_id: str,
    *,
    name: str | None = None,
    description: str | None = None,
    effect: str | None = None,
    priority: int | None = None,
    conditions: list[dict[str, Any]] | None = None,
    target_agents: list[str] | None = None,
    target_actions: list[str] | None = None,
    target_resources: list[str] | None = None,
    enabled: bool | None = None,
) -> dict[str, Any]:
    """Update a policy rule (creates new version)."""
    rule = _rules.get(rule_id)
    if not rule:
        raise KeyError(f"rule not found: {rule_id}")

    if effect is not None and effect not in VALID_EFFECTS:
        raise ValueError(f"invalid effect: {effect}")
    if priority is not None and (priority < 0 or priority > 1000):
        raise ValueError("priority must be 0-1000")

    if name is not None:
        rule["name"] = name
    if description is not None:
        rule["description"] = description
    if effect is not None:
        rule["effect"] = effect
    if priority is not None:
        rule["priority"] = priority
    if conditions is not None:
        rule["conditions"] = _parse_conditions(conditions)
    if target_agents is not None:
        rule["target_agents"] = target_agents
    if target_actions is not None:
        rule["target_actions"] = target_actions
    if target_resources is not None:
        rule["target_resources"] = target_resources
    if enabled is not None:
        rule["enabled"] = enabled

    rule["version"] += 1
    rule["updated_at"] = time.time()

    _record_version(rule, "updated")
    return rule


def get_rule(rule_id: str) -> dict[str, Any]:
    """Get a policy rule."""
    rule = _rules.get(rule_id)
    if not rule:
        raise KeyError(f"rule not found: {rule_id}")
    return rule


def delete_rule(rule_id: str) -> dict[str, Any]:
    """Delete a policy rule."""
    rule = _rules.pop(rule_id, None)
    if not rule:
        raise KeyError(f"rule not found: {rule_id}")
    _record_version(rule, "deleted")
    return {"deleted": True, "rule_id": rule_id}


def list_rules(
    *,
    enabled_only: bool = False,
    effect: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List rules sorted by priority (highest first)."""
    results = list(_rules.values())
    if enabled_only:
        results = [r for r in results if r["enabled"]]
    if effect:
        results = [r for r in results if r["effect"] == effect]
    results.sort(key=lambda r: r["priority"], reverse=True)
    return results[:limit]


def evaluate(
    *,
    agent_id: str,
    action: str,
    resource: str | None = None,
    context: dict[str, Any] | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Evaluate all rules against a request. Returns the decision."""
    ctx = context or {}
    ctx["agent_id"] = agent_id
    ctx["action"] = action
    ctx["resource"] = resource or ""

    # Get enabled rules sorted by priority (highest first)
    active_rules = sorted(
        (r for r in _rules.values() if r["enabled"]),
        key=lambda r: r["priority"],
        reverse=True,
    )

    matched_rules: list[dict[str, Any]] = []
    final_effect = EFFECT_ALLOW  # default allow

    for rule in active_rules:
        if _rule_matches(rule, ctx):
            matched_rules.append({
                "rule_id": rule["rule_id"],
                "name": rule["name"],
                "effect": rule["effect"],
                "priority": rule["priority"],
            })
            # First matching deny wins (deny-overrides)
            if rule["effect"] == EFFECT_DENY:
                final_effect = EFFECT_DENY
                break
            elif rule["effect"] == EFFECT_REQUIRE_APPROVAL:
                final_effect = EFFECT_REQUIRE_APPROVAL
                # Don't break — a higher-priority deny could still override
            elif rule["effect"] == EFFECT_ALLOW and final_effect != EFFECT_REQUIRE_APPROVAL:
                final_effect = EFFECT_ALLOW

    result: dict[str, Any] = {
        "decision": final_effect,
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "matched_rules": matched_rules,
        "total_rules_evaluated": len(active_rules),
        "dry_run": dry_run,
        "timestamp": time.time(),
    }

    if not dry_run:
        eval_id = f"eval-{uuid.uuid4().hex[:12]}"
        result["evaluation_id"] = eval_id
        _evaluations.append(result)
        if len(_evaluations) > _MAX_RECORDS:
            _evaluations[:] = _evaluations[-_MAX_RECORDS:]

    return result


def get_evaluation_log(
    *,
    agent_id: str | None = None,
    decision: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Get evaluation history."""
    results: list[dict[str, Any]] = []
    for ev in reversed(_evaluations):
        if agent_id and ev.get("agent_id") != agent_id:
            continue
        if decision and ev.get("decision") != decision:
            continue
        results.append(ev)
        if len(results) >= limit:
            break
    return results


def get_rule_versions(rule_id: str) -> list[dict[str, Any]]:
    """Get version history for a rule."""
    return [v for v in _rule_versions if v["rule_id"] == rule_id]


# ── Internal helpers ─────────────────────────────────────────────────

def _parse_conditions(conditions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate and parse conditions."""
    parsed: list[dict[str, Any]] = []
    for cond in conditions:
        attr = cond.get("attribute", "")
        op = cond.get("operator", "")
        value = cond.get("value")

        if not attr:
            raise ValueError("condition missing 'attribute'")
        if op not in VALID_OPERATORS:
            raise ValueError(f"invalid operator: {op}")

        parsed.append({"attribute": attr, "operator": op, "value": value})
    return parsed


def _rule_matches(rule: dict[str, Any], ctx: dict[str, Any]) -> bool:
    """Check if a rule matches the evaluation context."""
    # Target agent filter
    if rule.get("target_agents"):
        if ctx.get("agent_id") not in rule["target_agents"]:
            return False

    # Target action filter (supports glob patterns)
    if rule.get("target_actions"):
        action = ctx.get("action", "")
        if not any(_pattern_match(p, action) for p in rule["target_actions"]):
            return False

    # Target resource filter
    if rule.get("target_resources"):
        resource = ctx.get("resource", "")
        if not any(_pattern_match(p, resource) for p in rule["target_resources"]):
            return False

    # Evaluate conditions
    for cond in rule.get("conditions", []):
        if not _evaluate_condition(cond, ctx):
            return False

    return True


def _evaluate_condition(cond: dict[str, Any], ctx: dict[str, Any]) -> bool:
    """Evaluate a single condition against context."""
    attr = cond["attribute"]
    op = cond["operator"]
    expected = cond["value"]

    actual = ctx.get(attr)

    if op == OP_EQUALS:
        return actual == expected
    elif op == OP_NOT_EQUALS:
        return actual != expected
    elif op == OP_IN:
        return actual in (expected if isinstance(expected, list) else [expected])
    elif op == OP_NOT_IN:
        return actual not in (expected if isinstance(expected, list) else [expected])
    elif op == OP_MATCHES:
        try:
            return bool(re.search(str(expected), str(actual or "")))
        except re.error:
            return False
    elif op == OP_GREATER_THAN:
        try:
            return float(actual or 0) > float(expected)
        except (TypeError, ValueError):
            return False
    elif op == OP_LESS_THAN:
        try:
            return float(actual or 0) < float(expected)
        except (TypeError, ValueError):
            return False
    return False


def _pattern_match(pattern: str, value: str) -> bool:
    """Match a pattern with wildcard support (* = any)."""
    if pattern == "*":
        return True
    if "*" in pattern:
        regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
        return bool(re.match(regex, value))
    return pattern == value


def _record_version(rule: dict[str, Any], action: str) -> None:
    """Record a rule version in history."""
    version_entry: dict[str, Any] = {
        "rule_id": rule["rule_id"],
        "version": rule["version"],
        "action": action,
        "snapshot": dict(rule),
        "timestamp": time.time(),
    }
    _rule_versions.append(version_entry)
    if len(_rule_versions) > _MAX_RECORDS:
        _rule_versions[:] = _rule_versions[-_MAX_RECORDS:]


def reset_for_tests() -> None:
    """Clear all policy data for testing."""
    _rules.clear()
    _rule_versions.clear()
    _evaluations.clear()
