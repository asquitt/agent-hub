from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from src.common.time import iso_from_epoch, utc_now_epoch
from src.runtime.constants import (
    DEFAULT_CPU_CORES,
    DEFAULT_DISK_IO_MB,
    DEFAULT_MEMORY_MB,
    DEFAULT_NETWORK_MODE,
    DEFAULT_TIMEOUT_SECONDS,
    EXEC_COMPLETED,
    EXEC_FAILED,
    EXEC_PENDING,
    EXEC_RUNNING,
    MAX_CPU_CORES,
    MAX_DISK_IO_MB,
    MAX_MEMORY_MB,
    MAX_TIMEOUT_SECONDS,
    SANDBOX_COMPLETED,
    SANDBOX_EXECUTING,
    SANDBOX_FAILED,
    SANDBOX_PENDING,
    SANDBOX_PROVISIONING,
    SANDBOX_READY,
    SANDBOX_TERMINATED,
    SANDBOX_TIMED_OUT,
    SANDBOX_TRANSITIONS,
    VALID_LOG_LEVELS,
    VALID_NETWORK_MODES,
)
from src.runtime.storage import RUNTIME_STORAGE
from src.runtime.types import (
    ResourceLimits,
    SandboxExecution,
    SandboxInstance,
    SandboxLogEntry,
    SandboxMetricSnapshot,
)


def _validate_transition(current: str, target: str) -> None:
    allowed = SANDBOX_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise ValueError(f"invalid state transition: {current} -> {target}")


def _validate_resource_limits(limits: ResourceLimits) -> None:
    if limits["cpu_cores"] <= 0 or limits["cpu_cores"] > MAX_CPU_CORES:
        raise ValueError(f"cpu_cores must be between 0 and {MAX_CPU_CORES}")
    if limits["memory_mb"] <= 0 or limits["memory_mb"] > MAX_MEMORY_MB:
        raise ValueError(f"memory_mb must be between 0 and {MAX_MEMORY_MB}")
    if limits["timeout_seconds"] <= 0 or limits["timeout_seconds"] > MAX_TIMEOUT_SECONDS:
        raise ValueError(f"timeout_seconds must be between 0 and {MAX_TIMEOUT_SECONDS}")
    if limits["network_mode"] not in VALID_NETWORK_MODES:
        raise ValueError(f"invalid network_mode: {limits['network_mode']}")
    if limits["disk_io_mb"] <= 0 or limits["disk_io_mb"] > MAX_DISK_IO_MB:
        raise ValueError(f"disk_io_mb must be between 0 and {MAX_DISK_IO_MB}")


def _resolve_limits(
    profile_id: str | None = None,
    resource_limits: dict[str, Any] | None = None,
) -> tuple[str | None, ResourceLimits]:
    if profile_id:
        profile = RUNTIME_STORAGE.get_profile(profile_id)
        return profile["profile_id"], profile["resource_limits"]

    if resource_limits:
        limits = ResourceLimits(
            cpu_cores=resource_limits.get("cpu_cores", DEFAULT_CPU_CORES),
            memory_mb=resource_limits.get("memory_mb", DEFAULT_MEMORY_MB),
            timeout_seconds=resource_limits.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS),
            network_mode=resource_limits.get("network_mode", DEFAULT_NETWORK_MODE),
            disk_io_mb=resource_limits.get("disk_io_mb", DEFAULT_DISK_IO_MB),
        )
        _validate_resource_limits(limits)
        return None, limits

    # Default to micro preset
    return None, ResourceLimits(
        cpu_cores=DEFAULT_CPU_CORES,
        memory_mb=DEFAULT_MEMORY_MB,
        timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
        network_mode=DEFAULT_NETWORK_MODE,
        disk_io_mb=DEFAULT_DISK_IO_MB,
    )


def _verify_agent_identity(agent_id: str) -> dict[str, Any] | None:
    try:
        from src.identity.storage import IDENTITY_STORAGE

        identity = IDENTITY_STORAGE.get_identity(agent_id)
        if identity["status"] != "active":
            raise PermissionError(f"agent {agent_id} is {identity['status']}")
        return dict(identity)
    except (KeyError, RuntimeError):
        return None


def create_sandbox(
    *,
    agent_id: str,
    owner: str,
    profile_id: str | None = None,
    profile_name: str | None = None,
    resource_limits: dict[str, Any] | None = None,
    delegation_id: str | None = None,
    lease_id: str | None = None,
) -> SandboxInstance:
    # Resolve profile by name if given
    resolved_profile_id = profile_id
    if profile_name and not profile_id:
        profile = RUNTIME_STORAGE.get_profile_by_name(profile_name)
        if profile:
            resolved_profile_id = profile["profile_id"]

    pid, limits = _resolve_limits(resolved_profile_id, resource_limits)
    _validate_resource_limits(limits)

    sandbox_id = f"sbx-{uuid.uuid4().hex[:16]}"

    instance = RUNTIME_STORAGE.insert_instance(
        sandbox_id=sandbox_id,
        profile_id=pid,
        agent_id=agent_id,
        owner=owner,
        status=SANDBOX_PENDING,
        cpu_cores=limits["cpu_cores"],
        memory_mb=limits["memory_mb"],
        timeout_seconds=limits["timeout_seconds"],
        network_mode=limits["network_mode"],
        disk_io_mb=limits["disk_io_mb"],
        delegation_id=delegation_id,
        lease_id=lease_id,
    )

    # Auto-transition through provisioning to ready (simulated control plane)
    RUNTIME_STORAGE.update_instance_status(sandbox_id, SANDBOX_PROVISIONING)
    now = iso_from_epoch(utc_now_epoch())
    instance = RUNTIME_STORAGE.update_instance_status(
        sandbox_id, SANDBOX_READY, started_at=now
    )

    RUNTIME_STORAGE.insert_log(
        sandbox_id=sandbox_id,
        execution_id=None,
        level="info",
        message=f"Sandbox provisioned: {limits['cpu_cores']} CPU, {limits['memory_mb']}MB RAM, {limits['timeout_seconds']}s timeout",
    )

    return instance


def get_sandbox(sandbox_id: str, owner: str) -> SandboxInstance:
    instance = RUNTIME_STORAGE.get_instance(sandbox_id)
    if instance["owner"] != owner:
        raise PermissionError("owner mismatch")
    return instance


def list_sandboxes(
    *,
    owner: str | None = None,
    agent_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[SandboxInstance]:
    return RUNTIME_STORAGE.list_instances(
        owner=owner, agent_id=agent_id, status=status, limit=limit,
    )


def start_execution(
    sandbox_id: str,
    *,
    owner: str,
    input_data: dict[str, Any],
) -> SandboxExecution:
    instance = RUNTIME_STORAGE.get_instance(sandbox_id)
    if instance["owner"] != owner:
        raise PermissionError("owner mismatch")
    if instance["status"] != SANDBOX_READY:
        raise ValueError(f"sandbox must be in 'ready' state, got '{instance['status']}'")

    input_hash = hashlib.sha256(
        json.dumps(input_data, sort_keys=True).encode()
    ).hexdigest()

    execution_id = f"exec-{uuid.uuid4().hex[:16]}"

    RUNTIME_STORAGE.update_instance_status(sandbox_id, SANDBOX_EXECUTING)

    execution = RUNTIME_STORAGE.insert_execution(
        execution_id=execution_id,
        sandbox_id=sandbox_id,
        agent_id=instance["agent_id"],
        owner=owner,
        status=EXEC_RUNNING,
        input_hash=input_hash,
    )

    RUNTIME_STORAGE.insert_log(
        sandbox_id=sandbox_id,
        execution_id=execution_id,
        level="info",
        message=f"Execution started: input_hash={input_hash[:16]}...",
    )

    return execution


def complete_execution(
    execution_id: str,
    *,
    owner: str,
    output_data: dict[str, Any] | None = None,
    exit_code: int = 0,
    error_message: str | None = None,
) -> SandboxExecution:
    execution = RUNTIME_STORAGE.get_execution(execution_id)
    if execution["owner"] != owner:
        raise PermissionError("owner mismatch")

    output_hash = None
    if output_data:
        output_hash = hashlib.sha256(
            json.dumps(output_data, sort_keys=True).encode()
        ).hexdigest()

    now = iso_from_epoch(utc_now_epoch())
    started_epoch = utc_now_epoch()  # approximate for duration
    status = EXEC_COMPLETED if exit_code == 0 and not error_message else EXEC_FAILED

    execution = RUNTIME_STORAGE.update_execution(
        execution_id,
        status=status,
        output_hash=output_hash,
        completed_at=now,
        duration_ms=0.0,  # control plane doesn't measure real execution time
        exit_code=exit_code,
        error_message=error_message,
    )

    # Transition sandbox back to ready or completed/failed
    sandbox = RUNTIME_STORAGE.get_instance(execution["sandbox_id"])
    if status == EXEC_COMPLETED:
        RUNTIME_STORAGE.update_instance_status(execution["sandbox_id"], SANDBOX_READY)
    else:
        RUNTIME_STORAGE.update_instance_status(execution["sandbox_id"], SANDBOX_FAILED)

    RUNTIME_STORAGE.insert_log(
        sandbox_id=execution["sandbox_id"],
        execution_id=execution_id,
        level="info" if status == EXEC_COMPLETED else "error",
        message=f"Execution {status}: exit_code={exit_code}",
    )

    return execution


def terminate_sandbox(
    sandbox_id: str,
    *,
    owner: str,
    reason: str = "manual_termination",
) -> SandboxInstance:
    instance = RUNTIME_STORAGE.get_instance(sandbox_id)
    if instance["owner"] != owner:
        raise PermissionError("owner mismatch")

    terminal_states = {SANDBOX_COMPLETED, SANDBOX_FAILED, SANDBOX_TERMINATED, SANDBOX_TIMED_OUT}
    if instance["status"] in terminal_states:
        raise ValueError(f"sandbox already in terminal state: {instance['status']}")

    now = iso_from_epoch(utc_now_epoch())

    # If executing, fail the active execution
    if instance["status"] == SANDBOX_EXECUTING:
        executions = RUNTIME_STORAGE.list_executions(
            sandbox_id=sandbox_id, status=EXEC_RUNNING
        )
        for exec_record in executions:
            RUNTIME_STORAGE.update_execution(
                exec_record["execution_id"],
                status=EXEC_FAILED,
                completed_at=now,
                error_message=f"Terminated: {reason}",
            )

    instance = RUNTIME_STORAGE.update_instance_status(
        sandbox_id,
        SANDBOX_TERMINATED,
        terminated_at=now,
        termination_reason=reason,
    )

    RUNTIME_STORAGE.insert_log(
        sandbox_id=sandbox_id,
        execution_id=None,
        level="warn",
        message=f"Sandbox terminated: {reason}",
    )

    return instance


def get_execution(execution_id: str, owner: str) -> SandboxExecution:
    execution = RUNTIME_STORAGE.get_execution(execution_id)
    if execution["owner"] != owner:
        raise PermissionError("owner mismatch")
    return execution


def list_executions(
    *,
    sandbox_id: str | None = None,
    agent_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[SandboxExecution]:
    return RUNTIME_STORAGE.list_executions(
        sandbox_id=sandbox_id, agent_id=agent_id, status=status, limit=limit,
    )


def get_logs(sandbox_id: str, owner: str, execution_id: str | None = None) -> list[SandboxLogEntry]:
    instance = RUNTIME_STORAGE.get_instance(sandbox_id)
    if instance["owner"] != owner:
        raise PermissionError("owner mismatch")
    return RUNTIME_STORAGE.list_logs(sandbox_id, execution_id=execution_id)


def get_metrics(sandbox_id: str, owner: str, execution_id: str | None = None) -> list[SandboxMetricSnapshot]:
    instance = RUNTIME_STORAGE.get_instance(sandbox_id)
    if instance["owner"] != owner:
        raise PermissionError("owner mismatch")
    return RUNTIME_STORAGE.list_metrics(sandbox_id, execution_id=execution_id)


def record_metric_snapshot(
    sandbox_id: str,
    *,
    execution_id: str | None = None,
    cpu_used: float = 0.0,
    memory_used_mb: int = 0,
    disk_io_mb: float = 0.0,
    network_bytes: int = 0,
) -> SandboxMetricSnapshot:
    return RUNTIME_STORAGE.insert_metric(
        sandbox_id=sandbox_id,
        execution_id=execution_id,
        cpu_used=cpu_used,
        memory_used_mb=memory_used_mb,
        disk_io_mb=disk_io_mb,
        network_bytes=network_bytes,
    )
