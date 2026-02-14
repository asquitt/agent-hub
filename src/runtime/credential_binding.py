"""Credential Binding Rules — context-aware credential restrictions.

Provides:
- Bind credentials to specific contexts (IP, environment, agent version)
- Validate credential usage against binding rules
- Auto-invalidate on context mismatch
- Binding audit log
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.credential_binding")

_MAX_RECORDS = 10_000
_bindings: dict[str, dict[str, Any]] = {}  # binding_id -> binding
_validations: list[dict[str, Any]] = []

BINDING_TYPES = {"ip", "environment", "agent_version", "network", "custom"}


def create_binding(
    *,
    credential_id: str,
    agent_id: str,
    binding_type: str,
    constraints: dict[str, Any],
    enforce: bool = True,
    description: str = "",
) -> dict[str, Any]:
    """Create a credential binding rule."""
    if binding_type not in BINDING_TYPES:
        raise ValueError(f"invalid binding type: {binding_type}")
    if not constraints:
        raise ValueError("constraints cannot be empty")

    binding_id = f"bind-{uuid.uuid4().hex[:12]}"
    now = time.time()

    binding: dict[str, Any] = {
        "binding_id": binding_id,
        "credential_id": credential_id,
        "agent_id": agent_id,
        "binding_type": binding_type,
        "constraints": constraints,
        "enforce": enforce,
        "description": description,
        "active": True,
        "created_at": now,
        "validation_count": 0,
        "violation_count": 0,
    }

    _bindings[binding_id] = binding
    if len(_bindings) > _MAX_RECORDS:
        oldest = sorted(_bindings, key=lambda k: _bindings[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _bindings[k]

    return binding


def get_binding(binding_id: str) -> dict[str, Any]:
    """Get binding details."""
    binding = _bindings.get(binding_id)
    if not binding:
        raise KeyError(f"binding not found: {binding_id}")
    return binding


def list_bindings(
    *,
    credential_id: str | None = None,
    agent_id: str | None = None,
    binding_type: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List binding rules."""
    results: list[dict[str, Any]] = []
    for b in _bindings.values():
        if credential_id and b["credential_id"] != credential_id:
            continue
        if agent_id and b["agent_id"] != agent_id:
            continue
        if binding_type and b["binding_type"] != binding_type:
            continue
        results.append(b)
        if len(results) >= limit:
            break
    return results


def validate_binding(
    *,
    credential_id: str,
    agent_id: str,
    context: dict[str, Any],
) -> dict[str, Any]:
    """Validate credential usage against all binding rules."""
    applicable = [
        b for b in _bindings.values()
        if b["credential_id"] == credential_id
        and b["agent_id"] == agent_id
        and b["active"]
    ]

    if not applicable:
        return {
            "valid": True,
            "credential_id": credential_id,
            "agent_id": agent_id,
            "reason": "no_bindings",
        }

    violations: list[dict[str, Any]] = []
    for binding in applicable:
        binding["validation_count"] += 1
        result = _check_constraints(binding, context)
        if not result["satisfied"]:
            binding["violation_count"] += 1
            violations.append({
                "binding_id": binding["binding_id"],
                "binding_type": binding["binding_type"],
                "reason": result["reason"],
                "enforce": binding["enforce"],
            })

    enforced_violations = [v for v in violations if v["enforce"]]
    valid = len(enforced_violations) == 0

    validation: dict[str, Any] = {
        "valid": valid,
        "credential_id": credential_id,
        "agent_id": agent_id,
        "bindings_checked": len(applicable),
        "violations": violations,
        "timestamp": time.time(),
    }

    _validations.append(validation)
    if len(_validations) > _MAX_RECORDS:
        _validations[:] = _validations[-_MAX_RECORDS:]

    return validation


def deactivate_binding(binding_id: str) -> dict[str, Any]:
    """Deactivate a binding rule."""
    binding = _bindings.get(binding_id)
    if not binding:
        raise KeyError(f"binding not found: {binding_id}")
    binding["active"] = False
    return binding


def get_validation_log(
    *,
    credential_id: str | None = None,
    agent_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Get validation log."""
    results: list[dict[str, Any]] = []
    for v in reversed(_validations):
        if credential_id and v["credential_id"] != credential_id:
            continue
        if agent_id and v["agent_id"] != agent_id:
            continue
        results.append(v)
        if len(results) >= limit:
            break
    return results


def get_binding_stats() -> dict[str, Any]:
    """Get binding statistics."""
    total = len(_bindings)
    active = sum(1 for b in _bindings.values() if b["active"])
    total_validations = sum(b["validation_count"] for b in _bindings.values())
    total_violations = sum(b["violation_count"] for b in _bindings.values())

    return {
        "total_bindings": total,
        "active_bindings": active,
        "total_validations": total_validations,
        "total_violations": total_violations,
    }


# ── Internal helpers ─────────────────────────────────────────────────

def _check_constraints(
    binding: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    """Check if context satisfies binding constraints."""
    constraints = binding["constraints"]
    binding_type = binding["binding_type"]

    if binding_type == "ip":
        allowed_ips = constraints.get("allowed_ips", [])
        client_ip = context.get("ip", "")
        if allowed_ips and client_ip not in allowed_ips:
            return {"satisfied": False, "reason": f"IP {client_ip} not in allowed list"}

    elif binding_type == "environment":
        required_env = constraints.get("environment")
        current_env = context.get("environment", "")
        if required_env and current_env != required_env:
            return {"satisfied": False, "reason": f"environment mismatch: expected {required_env}, got {current_env}"}

    elif binding_type == "agent_version":
        required_version = constraints.get("min_version")
        current_version = context.get("agent_version", "0.0.0")
        if required_version and current_version < required_version:
            return {"satisfied": False, "reason": f"version too old: {current_version} < {required_version}"}

    elif binding_type == "network":
        allowed_cidrs = constraints.get("allowed_cidrs", [])
        client_ip = context.get("ip", "")
        if allowed_cidrs and not any(client_ip.startswith(cidr.split("/")[0].rsplit(".", 1)[0]) for cidr in allowed_cidrs):
            return {"satisfied": False, "reason": f"IP {client_ip} not in allowed networks"}

    elif binding_type == "custom":
        # Custom constraints: check each key-value against context
        for key, expected in constraints.items():
            actual = context.get(key)
            if actual != expected:
                return {"satisfied": False, "reason": f"custom constraint failed: {key}={actual}, expected {expected}"}

    return {"satisfied": True, "reason": "all constraints met"}


def reset_for_tests() -> None:
    """Clear all binding data for testing."""
    _bindings.clear()
    _validations.clear()
