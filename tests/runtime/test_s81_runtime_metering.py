"""S81: Runtime metering — cost tracking for sandbox operations."""

from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key-001": "test-owner"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-signing-secret-s81")

from src.cost_governance.service import list_metering_events
from src.runtime.metering import (
    BASE_PROVISION_FEE,
    CPU_RATE_PER_SECOND,
    MEMORY_RATE_PER_MB_SECOND,
    estimate_execution_cost,
    meter_sandbox_execution,
    meter_sandbox_provision,
    meter_sandbox_termination,
)
from src.runtime.types import ResourceLimits


def test_provision_metering():
    """Provision event is recorded with correct cost."""
    limits = ResourceLimits(
        cpu_cores=1.0, memory_mb=1024, timeout_seconds=300,
        network_mode="disabled", disk_io_mb=256,
    )
    event = meter_sandbox_provision(
        sandbox_id="sbx-meter-1",
        agent_id="meter-agent",
        owner="test-owner",
        resource_limits=limits,
    )
    assert event["operation"] == "runtime.sandbox.provision"
    assert event["cost_usd"] == BASE_PROVISION_FEE
    assert event["metadata"]["sandbox_id"] == "sbx-meter-1"
    assert event["metadata"]["cpu_cores"] == 1.0
    print("PASS: provision metering")


def test_execution_metering():
    """Execution event records correct cost calculation."""
    limits = ResourceLimits(
        cpu_cores=1.0, memory_mb=1024, timeout_seconds=300,
        network_mode="full", disk_io_mb=256,
    )
    event = meter_sandbox_execution(
        sandbox_id="sbx-meter-2",
        execution_id="exec-meter-1",
        agent_id="meter-agent",
        owner="test-owner",
        duration_seconds=60.0,
        resource_limits=limits,
        network_bytes=1_000_000,
    )
    assert event["operation"] == "runtime.sandbox.execute"
    assert event["cost_usd"] > 0
    meta = event["metadata"]
    assert meta["duration_seconds"] == 60.0
    assert meta["cpu_cost_usd"] == round(1.0 * 60.0 * CPU_RATE_PER_SECOND, 8)
    assert meta["memory_cost_usd"] == round(1024 * 60.0 * MEMORY_RATE_PER_MB_SECOND, 8)
    assert meta["network_bytes"] == 1_000_000
    print("PASS: execution metering")


def test_termination_metering():
    """Termination event is recorded with zero cost."""
    event = meter_sandbox_termination(
        sandbox_id="sbx-meter-3",
        agent_id="meter-agent",
        owner="test-owner",
        reason="test_cleanup",
    )
    assert event["operation"] == "runtime.sandbox.terminate"
    assert event["cost_usd"] == 0.0
    assert event["metadata"]["reason"] == "test_cleanup"
    print("PASS: termination metering")


def test_cost_estimation():
    """Cost estimation produces reasonable values."""
    limits = ResourceLimits(
        cpu_cores=2.0, memory_mb=4096, timeout_seconds=600,
        network_mode="full", disk_io_mb=1024,
    )
    cost = estimate_execution_cost(limits, estimated_duration_seconds=300.0)
    expected_cpu = 2.0 * 300.0 * CPU_RATE_PER_SECOND
    expected_mem = 4096 * 300.0 * MEMORY_RATE_PER_MB_SECOND
    expected = round(BASE_PROVISION_FEE + expected_cpu + expected_mem, 8)
    assert cost == expected
    assert cost > 0
    print("PASS: cost estimation")


def test_metering_events_in_global_list():
    """Runtime metering events appear in the global metering event list."""
    events = list_metering_events(limit=50)
    runtime_events = [e for e in events if e["operation"].startswith("runtime.")]
    assert len(runtime_events) >= 1
    print("PASS: metering events in global list")


if __name__ == "__main__":
    test_provision_metering()
    test_execution_metering()
    test_termination_metering()
    test_cost_estimation()
    test_metering_events_in_global_list()
    print("\nAll S81 metering tests passed!")
