"""Environment-Based Access Controls (S156).

Restrict agent operations based on deployment environment (dev/staging/prod)
with promotion gates and environment-specific policies.
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.env_access")

_MAX_RECORDS = 10_000
_environments: dict[str, dict[str, Any]] = {}  # env_id -> environment
_env_policies: dict[str, dict[str, Any]] = {}  # policy_id -> policy
_promotions: list[dict[str, Any]] = []  # promotion log

VALID_ENV_TIERS = ("development", "staging", "production")
TIER_ORDER = {t: i for i, t in enumerate(VALID_ENV_TIERS)}


def create_environment(
    *,
    name: str,
    tier: str,
    description: str = "",
    allowed_actions: list[str] | None = None,
    max_agents: int = 0,
) -> dict[str, Any]:
    """Create a deployment environment."""
    if tier not in VALID_ENV_TIERS:
        raise ValueError(f"tier must be one of {VALID_ENV_TIERS}")

    env_id = f"env-{uuid.uuid4().hex[:12]}"
    now = time.time()

    env: dict[str, Any] = {
        "env_id": env_id,
        "name": name,
        "tier": tier,
        "description": description,
        "allowed_actions": allowed_actions or [],
        "max_agents": max_agents,
        "active_agents": [],
        "created_at": now,
    }
    _environments[env_id] = env

    if len(_environments) > _MAX_RECORDS:
        oldest = sorted(_environments, key=lambda k: _environments[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _environments[k]

    return env


def get_environment(env_id: str) -> dict[str, Any]:
    """Get environment details."""
    env = _environments.get(env_id)
    if not env:
        raise KeyError(f"environment not found: {env_id}")
    return env


def list_environments(*, tier: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    """List environments with optional tier filter."""
    results: list[dict[str, Any]] = []
    for env in sorted(_environments.values(), key=lambda e: e["created_at"], reverse=True):
        if tier and env["tier"] != tier:
            continue
        results.append(env)
        if len(results) >= limit:
            break
    return results


def register_agent(env_id: str, agent_id: str) -> dict[str, Any]:
    """Register an agent to an environment."""
    env = _environments.get(env_id)
    if not env:
        raise KeyError(f"environment not found: {env_id}")

    if env["max_agents"] > 0 and len(env["active_agents"]) >= env["max_agents"]:
        raise ValueError(f"environment {env_id} at capacity ({env['max_agents']} agents)")

    if agent_id not in env["active_agents"]:
        env["active_agents"].append(agent_id)

    return {"env_id": env_id, "agent_id": agent_id, "registered": True, "tier": env["tier"]}


def unregister_agent(env_id: str, agent_id: str) -> dict[str, Any]:
    """Remove an agent from an environment."""
    env = _environments.get(env_id)
    if not env:
        raise KeyError(f"environment not found: {env_id}")

    if agent_id in env["active_agents"]:
        env["active_agents"].remove(agent_id)

    return {"env_id": env_id, "agent_id": agent_id, "unregistered": True}


def check_access(
    *,
    agent_id: str,
    env_id: str,
    action: str,
) -> dict[str, Any]:
    """Check if an agent can perform an action in an environment."""
    env = _environments.get(env_id)
    if not env:
        raise KeyError(f"environment not found: {env_id}")

    # Agent must be registered
    if agent_id not in env["active_agents"]:
        return {
            "allowed": False,
            "reason": "agent_not_registered",
            "env_id": env_id,
            "agent_id": agent_id,
            "action": action,
        }

    # Check allowed actions (empty list = all allowed)
    if env["allowed_actions"] and action not in env["allowed_actions"]:
        return {
            "allowed": False,
            "reason": "action_not_allowed",
            "env_id": env_id,
            "agent_id": agent_id,
            "action": action,
            "allowed_actions": env["allowed_actions"],
        }

    # Check environment-level policies
    violations = _check_policies(agent_id=agent_id, env_id=env_id, action=action)
    if violations:
        return {
            "allowed": False,
            "reason": "policy_violation",
            "violations": violations,
            "env_id": env_id,
            "agent_id": agent_id,
            "action": action,
        }

    return {"allowed": True, "env_id": env_id, "agent_id": agent_id, "action": action, "tier": env["tier"]}


def create_policy(
    *,
    env_id: str,
    name: str,
    rules: dict[str, Any],
    description: str = "",
) -> dict[str, Any]:
    """Create an environment-level policy."""
    if env_id not in _environments:
        raise KeyError(f"environment not found: {env_id}")

    pid = f"epol-{uuid.uuid4().hex[:12]}"
    now = time.time()

    policy: dict[str, Any] = {
        "policy_id": pid,
        "env_id": env_id,
        "name": name,
        "rules": rules,
        "description": description,
        "enabled": True,
        "created_at": now,
    }
    _env_policies[pid] = policy

    if len(_env_policies) > _MAX_RECORDS:
        oldest = sorted(_env_policies, key=lambda k: _env_policies[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _env_policies[k]

    return policy


def list_policies(*, env_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    """List environment policies."""
    results: list[dict[str, Any]] = []
    for p in sorted(_env_policies.values(), key=lambda x: x["created_at"], reverse=True):
        if env_id and p["env_id"] != env_id:
            continue
        results.append(p)
        if len(results) >= limit:
            break
    return results


def promote_agent(
    *,
    agent_id: str,
    from_env_id: str,
    to_env_id: str,
) -> dict[str, Any]:
    """Promote an agent from one environment to another."""
    from_env = _environments.get(from_env_id)
    to_env = _environments.get(to_env_id)
    if not from_env:
        raise KeyError(f"source environment not found: {from_env_id}")
    if not to_env:
        raise KeyError(f"target environment not found: {to_env_id}")

    # Enforce tier ordering (can only promote up)
    from_tier = TIER_ORDER.get(from_env["tier"], -1)
    to_tier = TIER_ORDER.get(to_env["tier"], -1)
    if to_tier <= from_tier:
        raise ValueError(
            f"can only promote to higher tier: {from_env['tier']} -> {to_env['tier']} is not allowed"
        )

    # Agent must be in source environment
    if agent_id not in from_env["active_agents"]:
        raise ValueError(f"agent {agent_id} not registered in source environment {from_env_id}")

    # Check target capacity
    if to_env["max_agents"] > 0 and len(to_env["active_agents"]) >= to_env["max_agents"]:
        raise ValueError(f"target environment {to_env_id} at capacity")

    # Perform promotion
    from_env["active_agents"].remove(agent_id)
    if agent_id not in to_env["active_agents"]:
        to_env["active_agents"].append(agent_id)

    record: dict[str, Any] = {
        "agent_id": agent_id,
        "from_env_id": from_env_id,
        "to_env_id": to_env_id,
        "from_tier": from_env["tier"],
        "to_tier": to_env["tier"],
        "promoted_at": time.time(),
    }
    _promotions.append(record)
    if len(_promotions) > _MAX_RECORDS:
        _promotions[:] = _promotions[-_MAX_RECORDS:]

    return record


def get_promotion_log(*, agent_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    """Get promotion history."""
    results: list[dict[str, Any]] = []
    for rec in reversed(_promotions):
        if agent_id and rec["agent_id"] != agent_id:
            continue
        results.append(rec)
        if len(results) >= limit:
            break
    return results


def get_env_stats() -> dict[str, Any]:
    """Get environment access control statistics."""
    total = len(_environments)
    by_tier: dict[str, int] = {}
    total_agents = 0
    for env in _environments.values():
        by_tier[env["tier"]] = by_tier.get(env["tier"], 0) + 1
        total_agents += len(env["active_agents"])

    return {
        "total_environments": total,
        "by_tier": by_tier,
        "total_registered_agents": total_agents,
        "total_policies": len(_env_policies),
        "total_promotions": len(_promotions),
    }


# ── Internal helpers ─────────────────────────────────────────────────

def _check_policies(*, agent_id: str, env_id: str, action: str) -> list[str]:
    """Check environment policies for violations."""
    violations: list[str] = []
    for policy in _env_policies.values():
        if policy["env_id"] != env_id or not policy["enabled"]:
            continue
        rules = policy["rules"]
        blocked = rules.get("blocked_actions", [])
        if action in blocked:
            violations.append(f"policy '{policy['name']}' blocks action '{action}'")
    return violations


def reset_for_tests() -> None:
    """Clear all environment data for testing."""
    _environments.clear()
    _env_policies.clear()
    _promotions.clear()
