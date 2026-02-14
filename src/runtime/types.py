from __future__ import annotations

from typing import TypedDict


class ResourceLimits(TypedDict):
    cpu_cores: float
    memory_mb: int
    timeout_seconds: int
    network_mode: str  # "disabled" | "egress_only" | "full"
    disk_io_mb: int


class SandboxProfile(TypedDict):
    profile_id: str
    name: str
    description: str
    resource_limits: ResourceLimits
    created_by: str
    created_at: str
    updated_at: str


class SandboxInstance(TypedDict):
    sandbox_id: str
    profile_id: str | None
    agent_id: str
    owner: str
    status: str
    resource_limits: ResourceLimits
    delegation_id: str | None
    lease_id: str | None
    created_at: str
    updated_at: str
    started_at: str | None
    terminated_at: str | None
    termination_reason: str | None


class SandboxExecution(TypedDict):
    execution_id: str
    sandbox_id: str
    agent_id: str
    owner: str
    status: str
    input_hash: str
    output_hash: str | None
    started_at: str
    completed_at: str | None
    duration_ms: float | None
    exit_code: int | None
    error_message: str | None


class SandboxLogEntry(TypedDict):
    log_id: str
    sandbox_id: str
    execution_id: str | None
    level: str
    message: str
    timestamp: str


class SandboxMetricSnapshot(TypedDict):
    metric_id: str
    sandbox_id: str
    execution_id: str | None
    cpu_used: float
    memory_used_mb: int
    disk_io_mb: float
    network_bytes: int
    timestamp: str
