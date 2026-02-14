from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from typing import Any

from src.runtime.constants import (
    MAX_CPU_CORES,
    MAX_DISK_IO_MB,
    MAX_MEMORY_MB,
    MAX_TIMEOUT_SECONDS,
    VALID_NETWORK_MODES,
)
from src.runtime.types import ResourceLimits

POLICY_VERSION = "runtime-policy-v1"
DEFAULT_MAX_CONCURRENT_EXECUTIONS = 10


def _sign_decision(payload: str) -> str:
    secret = os.getenv("AGENTHUB_IDENTITY_SIGNING_SECRET", "unsigned")
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def _reason(
    code: str,
    message: str,
    rtype: str = "violation",
    field: str | None = None,
    expected: str | None = None,
    observed: str | None = None,
) -> dict[str, Any]:
    r: dict[str, Any] = {"code": code, "message": message, "type": rtype}
    if field:
        r["field"] = field
    if expected:
        r["expected"] = expected
    if observed:
        r["observed"] = observed
    return r


def _build_decision(
    *,
    context: str,
    action: str,
    actor: str,
    subject: dict[str, Any],
    reasons: list[dict[str, Any]],
) -> dict[str, Any]:
    violations = [r for r in reasons if r["type"] == "violation"]
    warnings = [r for r in reasons if r["type"] == "warning"]
    allows = [r for r in reasons if r["type"] == "allow"]

    allowed = len(violations) == 0
    decision = "allow" if allowed else "deny"

    decision_id = uuid.uuid4().hex[:24]
    input_hash = hashlib.sha256(
        json.dumps({"context": context, "actor": actor, "subject": subject}, sort_keys=True).encode()
    ).hexdigest()

    payload = f"{decision_id}:{decision}:{input_hash}"
    signature = _sign_decision(payload)

    return {
        "policy_version": POLICY_VERSION,
        "decision_id": decision_id,
        "context": context,
        "action": action,
        "actor": actor,
        "subject": subject,
        "decision": decision,
        "allowed": allowed,
        "reasons": reasons,
        "violated_constraints": [r["code"] for r in violations],
        "explainability": {
            "violation_codes": [r["code"] for r in violations],
            "warning_codes": [r["code"] for r in warnings],
            "allow_codes": [r["code"] for r in allows],
        },
        "input_hash": input_hash,
        "signature_algorithm": "sha256(secret+payload)",
        "decision_signature": signature,
    }


def evaluate_runtime_policy(
    *,
    actor: str,
    agent_id: str,
    resource_limits: ResourceLimits,
    org_limits: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reasons: list[dict[str, Any]] = []
    limits = org_limits or {}

    max_cpu = limits.get("max_cpu_cores", MAX_CPU_CORES)
    max_mem = limits.get("max_memory_mb", MAX_MEMORY_MB)
    max_timeout = limits.get("max_timeout_seconds", MAX_TIMEOUT_SECONDS)
    max_disk = limits.get("max_disk_io_mb", MAX_DISK_IO_MB)
    allowed_network_modes = limits.get("allowed_network_modes", list(VALID_NETWORK_MODES))

    if resource_limits["cpu_cores"] > max_cpu:
        reasons.append(_reason(
            "runtime.cpu_exceeded",
            f"CPU cores {resource_limits['cpu_cores']} exceeds org limit {max_cpu}",
            field="cpu_cores",
            expected=str(max_cpu),
            observed=str(resource_limits["cpu_cores"]),
        ))

    if resource_limits["memory_mb"] > max_mem:
        reasons.append(_reason(
            "runtime.memory_exceeded",
            f"Memory {resource_limits['memory_mb']}MB exceeds org limit {max_mem}MB",
            field="memory_mb",
            expected=str(max_mem),
            observed=str(resource_limits["memory_mb"]),
        ))

    if resource_limits["timeout_seconds"] > max_timeout:
        reasons.append(_reason(
            "runtime.timeout_exceeded",
            f"Timeout {resource_limits['timeout_seconds']}s exceeds org limit {max_timeout}s",
            field="timeout_seconds",
            expected=str(max_timeout),
            observed=str(resource_limits["timeout_seconds"]),
        ))

    if resource_limits["disk_io_mb"] > max_disk:
        reasons.append(_reason(
            "runtime.disk_exceeded",
            f"Disk I/O {resource_limits['disk_io_mb']}MB exceeds org limit {max_disk}MB",
            field="disk_io_mb",
            expected=str(max_disk),
            observed=str(resource_limits["disk_io_mb"]),
        ))

    if resource_limits["network_mode"] not in allowed_network_modes:
        reasons.append(_reason(
            "runtime.network_mode_denied",
            f"Network mode '{resource_limits['network_mode']}' not allowed",
            field="network_mode",
            expected=str(allowed_network_modes),
            observed=resource_limits["network_mode"],
        ))

    if not reasons:
        reasons.append(_reason(
            "runtime.within_limits",
            "All resource limits within policy bounds",
            rtype="allow",
        ))

    return _build_decision(
        context="runtime_sandbox",
        action="provision",
        actor=actor,
        subject={"agent_id": agent_id, "resource_limits": dict(resource_limits)},
        reasons=reasons,
    )


def evaluate_sandbox_execution_policy(
    *,
    actor: str,
    agent_id: str,
    active_execution_count: int,
    max_concurrent: int | None = None,
) -> dict[str, Any]:
    reasons: list[dict[str, Any]] = []
    limit = max_concurrent or DEFAULT_MAX_CONCURRENT_EXECUTIONS

    if active_execution_count >= limit:
        reasons.append(_reason(
            "runtime.max_concurrent_exceeded",
            f"Agent has {active_execution_count} active executions, limit is {limit}",
            field="active_execution_count",
            expected=str(limit),
            observed=str(active_execution_count),
        ))
    else:
        reasons.append(_reason(
            "runtime.concurrent_within_limit",
            f"Agent has {active_execution_count}/{limit} active executions",
            rtype="allow",
        ))

    return _build_decision(
        context="runtime_execution",
        action="execute",
        actor=actor,
        subject={"agent_id": agent_id, "active_execution_count": active_execution_count},
        reasons=reasons,
    )
