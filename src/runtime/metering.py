from __future__ import annotations

from typing import Any

from src.cost_governance.service import record_metering_event
from src.runtime.types import ResourceLimits

# Cost rates (per unit)
CPU_RATE_PER_SECOND = 0.00001  # $0.00001/core-second
MEMORY_RATE_PER_MB_SECOND = 0.000001  # $0.000001/MB-second
NETWORK_RATE_PER_GB = 0.01  # $0.01/GB
BASE_PROVISION_FEE = 0.001  # $0.001 per sandbox


def estimate_execution_cost(
    resource_limits: ResourceLimits,
    estimated_duration_seconds: float,
) -> float:
    cpu_cost = resource_limits["cpu_cores"] * estimated_duration_seconds * CPU_RATE_PER_SECOND
    mem_cost = resource_limits["memory_mb"] * estimated_duration_seconds * MEMORY_RATE_PER_MB_SECOND
    return round(BASE_PROVISION_FEE + cpu_cost + mem_cost, 8)


def meter_sandbox_provision(
    *,
    sandbox_id: str,
    agent_id: str,
    owner: str,
    resource_limits: ResourceLimits,
) -> dict[str, Any]:
    return record_metering_event(
        actor=owner,
        operation="runtime.sandbox.provision",
        cost_usd=BASE_PROVISION_FEE,
        metadata={
            "sandbox_id": sandbox_id,
            "agent_id": agent_id,
            "cpu_cores": resource_limits["cpu_cores"],
            "memory_mb": resource_limits["memory_mb"],
            "timeout_seconds": resource_limits["timeout_seconds"],
            "network_mode": resource_limits["network_mode"],
        },
    )


def meter_sandbox_execution(
    *,
    sandbox_id: str,
    execution_id: str,
    agent_id: str,
    owner: str,
    duration_seconds: float,
    resource_limits: ResourceLimits,
    network_bytes: int = 0,
) -> dict[str, Any]:
    cpu_cost = resource_limits["cpu_cores"] * duration_seconds * CPU_RATE_PER_SECOND
    mem_cost = resource_limits["memory_mb"] * duration_seconds * MEMORY_RATE_PER_MB_SECOND
    net_cost = (network_bytes / 1_073_741_824) * NETWORK_RATE_PER_GB  # bytes → GB
    total_cost = round(cpu_cost + mem_cost + net_cost, 8)

    return record_metering_event(
        actor=owner,
        operation="runtime.sandbox.execute",
        cost_usd=total_cost,
        metadata={
            "sandbox_id": sandbox_id,
            "execution_id": execution_id,
            "agent_id": agent_id,
            "duration_seconds": duration_seconds,
            "cpu_cost_usd": round(cpu_cost, 8),
            "memory_cost_usd": round(mem_cost, 8),
            "network_cost_usd": round(net_cost, 8),
            "network_bytes": network_bytes,
        },
    )


def meter_sandbox_termination(
    *,
    sandbox_id: str,
    agent_id: str,
    owner: str,
    reason: str,
) -> dict[str, Any]:
    return record_metering_event(
        actor=owner,
        operation="runtime.sandbox.terminate",
        cost_usd=0.0,
        metadata={
            "sandbox_id": sandbox_id,
            "agent_id": agent_id,
            "reason": reason,
        },
    )
