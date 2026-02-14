from __future__ import annotations

from typing import Any

from src.common.time import utc_now_iso
from src.runtime.storage import RUNTIME_STORAGE


def export_sandbox_evidence(
    *,
    actor: str,
    sandbox_id: str | None = None,
    agent_id: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Export sandbox execution evidence for compliance audits."""
    instances = RUNTIME_STORAGE.list_instances(
        agent_id=agent_id, limit=limit,
    )
    if sandbox_id:
        instances = [i for i in instances if i["sandbox_id"] == sandbox_id]

    executions = RUNTIME_STORAGE.list_executions(
        sandbox_id=sandbox_id, agent_id=agent_id, limit=limit,
    )

    return {
        "generated_at": utc_now_iso(),
        "generated_by": actor,
        "sandbox_count": len(instances),
        "execution_count": len(executions),
        "sandboxes": [dict(i) for i in instances],
        "executions": [dict(e) for e in executions],
    }


def check_sandbox_audit_completeness() -> dict[str, Any]:
    """Compliance check: verify sandbox execution records have required audit fields."""
    executions = RUNTIME_STORAGE.list_executions(limit=200)
    required_fields = {"execution_id", "sandbox_id", "agent_id", "owner", "status", "input_hash", "started_at"}

    invalid_count = 0
    for ex in executions:
        missing = [f for f in required_fields if not ex.get(f)]
        if missing:
            invalid_count += 1

    instances = RUNTIME_STORAGE.list_instances(limit=200)
    instance_required = {"sandbox_id", "agent_id", "owner", "status", "created_at"}
    for inst in instances:
        missing = [f for f in instance_required if not inst.get(f)]
        if missing:
            invalid_count += 1

    passed = invalid_count == 0
    return {
        "passed": passed,
        "evidence": {
            "execution_count": len(executions),
            "instance_count": len(instances),
            "invalid_count": invalid_count,
            "required_execution_fields": sorted(required_fields),
            "required_instance_fields": sorted(instance_required),
        },
    }
