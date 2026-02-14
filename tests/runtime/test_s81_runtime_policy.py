"""S81: Runtime policy — resource limit enforcement and rate limiting."""

from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key-001": "test-owner"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-signing-secret-s81")

from src.runtime.policy import evaluate_runtime_policy, evaluate_sandbox_execution_policy
from src.runtime.types import ResourceLimits


def test_within_limits_allowed():
    """Resource limits within bounds are allowed."""
    limits = ResourceLimits(
        cpu_cores=1.0, memory_mb=1024, timeout_seconds=300,
        network_mode="disabled", disk_io_mb=256,
    )
    decision = evaluate_runtime_policy(
        actor="test-owner", agent_id="agent-1", resource_limits=limits,
    )
    assert decision["allowed"] is True
    assert decision["decision"] == "allow"
    assert len(decision["violated_constraints"]) == 0
    assert decision["decision_signature"]  # signed
    print("PASS: within limits allowed")


def test_cpu_exceeded_denied():
    """CPU cores exceeding org limit are denied."""
    limits = ResourceLimits(
        cpu_cores=2.0, memory_mb=256, timeout_seconds=30,
        network_mode="disabled", disk_io_mb=100,
    )
    decision = evaluate_runtime_policy(
        actor="test-owner",
        agent_id="agent-1",
        resource_limits=limits,
        org_limits={"max_cpu_cores": 1.0},
    )
    assert decision["allowed"] is False
    assert "runtime.cpu_exceeded" in decision["violated_constraints"]
    print("PASS: CPU exceeded denied")


def test_memory_exceeded_denied():
    """Memory exceeding org limit is denied."""
    limits = ResourceLimits(
        cpu_cores=0.5, memory_mb=4096, timeout_seconds=30,
        network_mode="disabled", disk_io_mb=100,
    )
    decision = evaluate_runtime_policy(
        actor="test-owner",
        agent_id="agent-1",
        resource_limits=limits,
        org_limits={"max_memory_mb": 2048},
    )
    assert decision["allowed"] is False
    assert "runtime.memory_exceeded" in decision["violated_constraints"]
    print("PASS: memory exceeded denied")


def test_network_mode_denied():
    """Network mode not in allowed list is denied."""
    limits = ResourceLimits(
        cpu_cores=0.5, memory_mb=256, timeout_seconds=30,
        network_mode="full", disk_io_mb=100,
    )
    decision = evaluate_runtime_policy(
        actor="test-owner",
        agent_id="agent-1",
        resource_limits=limits,
        org_limits={"allowed_network_modes": ["disabled", "egress_only"]},
    )
    assert decision["allowed"] is False
    assert "runtime.network_mode_denied" in decision["violated_constraints"]
    print("PASS: network mode denied")


def test_timeout_exceeded_denied():
    """Timeout exceeding org limit is denied."""
    limits = ResourceLimits(
        cpu_cores=0.5, memory_mb=256, timeout_seconds=7200,
        network_mode="disabled", disk_io_mb=100,
    )
    decision = evaluate_runtime_policy(
        actor="test-owner",
        agent_id="agent-1",
        resource_limits=limits,
        org_limits={"max_timeout_seconds": 600},
    )
    assert decision["allowed"] is False
    assert "runtime.timeout_exceeded" in decision["violated_constraints"]
    print("PASS: timeout exceeded denied")


def test_multiple_violations():
    """Multiple policy violations are reported."""
    limits = ResourceLimits(
        cpu_cores=8.0, memory_mb=99999, timeout_seconds=30,
        network_mode="disabled", disk_io_mb=100,
    )
    decision = evaluate_runtime_policy(
        actor="test-owner",
        agent_id="agent-1",
        resource_limits=limits,
        org_limits={"max_cpu_cores": 2.0, "max_memory_mb": 4096},
    )
    assert decision["allowed"] is False
    assert len(decision["violated_constraints"]) >= 2
    print("PASS: multiple violations")


def test_decision_has_signature():
    """Policy decision is cryptographically signed."""
    limits = ResourceLimits(
        cpu_cores=0.25, memory_mb=256, timeout_seconds=30,
        network_mode="disabled", disk_io_mb=100,
    )
    decision = evaluate_runtime_policy(
        actor="test-owner", agent_id="agent-1", resource_limits=limits,
    )
    assert decision["decision_signature"]
    assert decision["signature_algorithm"] == "sha256(secret+payload)"
    assert decision["policy_version"] == "runtime-policy-v1"
    print("PASS: decision has signature")


def test_execution_within_concurrent_limit():
    """Execution within concurrent limit is allowed."""
    decision = evaluate_sandbox_execution_policy(
        actor="test-owner", agent_id="agent-1",
        active_execution_count=3, max_concurrent=10,
    )
    assert decision["allowed"] is True
    print("PASS: execution within concurrent limit")


def test_execution_exceeds_concurrent_limit():
    """Execution exceeding concurrent limit is denied."""
    decision = evaluate_sandbox_execution_policy(
        actor="test-owner", agent_id="agent-1",
        active_execution_count=10, max_concurrent=10,
    )
    assert decision["allowed"] is False
    assert "runtime.max_concurrent_exceeded" in decision["violated_constraints"]
    print("PASS: execution exceeds concurrent limit")


if __name__ == "__main__":
    test_within_limits_allowed()
    test_cpu_exceeded_denied()
    test_memory_exceeded_denied()
    test_network_mode_denied()
    test_timeout_exceeded_denied()
    test_multiple_violations()
    test_decision_has_signature()
    test_execution_within_concurrent_limit()
    test_execution_exceeds_concurrent_limit()
    print("\nAll S81 policy tests passed!")
