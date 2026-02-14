"""S80: Sandbox lifecycle — create, execute, complete, terminate."""

from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key-001": "test-owner"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-signing-secret-s80")

from starlette.testclient import TestClient

from src.api.app import app
from src.runtime.storage import reset_for_tests

HEADERS = {"X-API-Key": "test-key-001"}

client = TestClient(app)
reset_for_tests()


# ---- Sandbox creation ----


def test_create_sandbox_with_profile_name():
    """Create a sandbox using a profile name."""
    resp = client.post(
        "/v1/runtime/sandboxes",
        json={"agent_id": "test-agent-1", "profile_name": "micro"},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["sandbox_id"].startswith("sbx-")
    assert data["agent_id"] == "test-agent-1"
    assert data["status"] == "ready"
    assert data["resource_limits"]["cpu_cores"] == 0.25
    assert data["resource_limits"]["memory_mb"] == 256
    assert data["resource_limits"]["network_mode"] == "disabled"
    print("PASS: create sandbox with profile name")


def test_create_sandbox_with_explicit_limits():
    """Create a sandbox with explicit resource limits."""
    resp = client.post(
        "/v1/runtime/sandboxes",
        json={
            "agent_id": "test-agent-2",
            "resource_limits": {
                "cpu_cores": 1.0,
                "memory_mb": 1024,
                "timeout_seconds": 120,
                "network_mode": "egress_only",
                "disk_io_mb": 512,
            },
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "ready"
    assert data["resource_limits"]["cpu_cores"] == 1.0
    assert data["resource_limits"]["memory_mb"] == 1024
    assert data["resource_limits"]["network_mode"] == "egress_only"
    print("PASS: create sandbox with explicit limits")


def test_create_sandbox_default_limits():
    """Create a sandbox with default (micro) limits when nothing specified."""
    resp = client.post(
        "/v1/runtime/sandboxes",
        json={"agent_id": "test-agent-default"},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["resource_limits"]["cpu_cores"] == 0.25
    assert data["resource_limits"]["memory_mb"] == 256
    print("PASS: create sandbox default limits")


def test_get_sandbox():
    """Get sandbox by ID."""
    resp = client.post(
        "/v1/runtime/sandboxes",
        json={"agent_id": "test-agent-get", "profile_name": "small"},
        headers=HEADERS,
    )
    sandbox_id = resp.json()["sandbox_id"]

    resp = client.get(f"/v1/runtime/sandboxes/{sandbox_id}", headers=HEADERS)
    assert resp.status_code == 200, resp.text
    assert resp.json()["sandbox_id"] == sandbox_id
    assert resp.json()["status"] == "ready"
    print("PASS: get sandbox")


def test_get_nonexistent_sandbox_404():
    """Getting a nonexistent sandbox returns 404."""
    resp = client.get("/v1/runtime/sandboxes/sbx-nonexistent", headers=HEADERS)
    assert resp.status_code == 404, resp.text
    print("PASS: nonexistent sandbox 404")


# ---- Execution lifecycle ----


def test_full_execution_lifecycle():
    """Sandbox lifecycle: create → execute → complete."""
    # Create sandbox
    resp = client.post(
        "/v1/runtime/sandboxes",
        json={"agent_id": "lifecycle-agent", "profile_name": "micro"},
        headers=HEADERS,
    )
    assert resp.status_code == 200
    sandbox_id = resp.json()["sandbox_id"]
    assert resp.json()["status"] == "ready"

    # Start execution
    resp = client.post(
        f"/v1/runtime/sandboxes/{sandbox_id}/execute",
        json={"input_data": {"task": "test-task", "params": {"x": 1}}},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    exec_data = resp.json()
    assert exec_data["execution_id"].startswith("exec-")
    assert exec_data["status"] == "running"
    assert exec_data["input_hash"]  # non-empty

    # Sandbox should be in executing state
    resp = client.get(f"/v1/runtime/sandboxes/{sandbox_id}", headers=HEADERS)
    assert resp.json()["status"] == "executing"

    # Complete execution
    resp = client.post(
        f"/v1/runtime/sandboxes/{sandbox_id}/complete",
        json={"output_data": {"result": "success"}, "exit_code": 0},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "completed"
    assert resp.json()["exit_code"] == 0
    assert resp.json()["output_hash"]  # non-empty

    # Sandbox should be back to ready
    resp = client.get(f"/v1/runtime/sandboxes/{sandbox_id}", headers=HEADERS)
    assert resp.json()["status"] == "ready"

    print("PASS: full execution lifecycle")


def test_execution_with_failure():
    """Execution that fails sets sandbox to failed state."""
    resp = client.post(
        "/v1/runtime/sandboxes",
        json={"agent_id": "fail-agent", "profile_name": "micro"},
        headers=HEADERS,
    )
    sandbox_id = resp.json()["sandbox_id"]

    resp = client.post(
        f"/v1/runtime/sandboxes/{sandbox_id}/execute",
        json={"input_data": {"task": "will-fail"}},
        headers=HEADERS,
    )
    assert resp.status_code == 200

    resp = client.post(
        f"/v1/runtime/sandboxes/{sandbox_id}/complete",
        json={"exit_code": 1, "error_message": "segfault"},
        headers=HEADERS,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "failed"
    assert resp.json()["error_message"] == "segfault"

    # Sandbox should be in failed state
    resp = client.get(f"/v1/runtime/sandboxes/{sandbox_id}", headers=HEADERS)
    assert resp.json()["status"] == "failed"

    print("PASS: execution with failure")


def test_execute_non_ready_sandbox_rejected():
    """Cannot execute in a sandbox that is not in ready state."""
    resp = client.post(
        "/v1/runtime/sandboxes",
        json={"agent_id": "not-ready-agent", "profile_name": "micro"},
        headers=HEADERS,
    )
    sandbox_id = resp.json()["sandbox_id"]

    # Start an execution first (moves to executing)
    client.post(
        f"/v1/runtime/sandboxes/{sandbox_id}/execute",
        json={"input_data": {"task": "first"}},
        headers=HEADERS,
    )

    # Try to start another execution while one is running
    resp = client.post(
        f"/v1/runtime/sandboxes/{sandbox_id}/execute",
        json={"input_data": {"task": "second"}},
        headers=HEADERS,
    )
    assert resp.status_code == 400, resp.text
    print("PASS: execute non-ready sandbox rejected")


# ---- Termination ----


def test_terminate_ready_sandbox():
    """Terminate a sandbox in ready state."""
    resp = client.post(
        "/v1/runtime/sandboxes",
        json={"agent_id": "term-agent", "profile_name": "micro"},
        headers=HEADERS,
    )
    sandbox_id = resp.json()["sandbox_id"]

    resp = client.post(
        f"/v1/runtime/sandboxes/{sandbox_id}/terminate",
        json={"reason": "test_cleanup"},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "terminated"
    assert resp.json()["termination_reason"] == "test_cleanup"
    print("PASS: terminate ready sandbox")


def test_terminate_executing_sandbox():
    """Terminate a sandbox that is currently executing."""
    resp = client.post(
        "/v1/runtime/sandboxes",
        json={"agent_id": "term-exec-agent", "profile_name": "micro"},
        headers=HEADERS,
    )
    sandbox_id = resp.json()["sandbox_id"]

    # Start execution
    resp = client.post(
        f"/v1/runtime/sandboxes/{sandbox_id}/execute",
        json={"input_data": {"task": "long-task"}},
        headers=HEADERS,
    )
    exec_id = resp.json()["execution_id"]

    # Terminate while executing
    resp = client.post(
        f"/v1/runtime/sandboxes/{sandbox_id}/terminate",
        json={"reason": "force_kill"},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "terminated"

    # Execution should be failed
    resp = client.get(f"/v1/runtime/executions/{exec_id}", headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["status"] == "failed"
    assert "Terminated" in resp.json()["error_message"]
    print("PASS: terminate executing sandbox")


def test_terminate_already_terminated_rejected():
    """Cannot terminate an already-terminated sandbox."""
    resp = client.post(
        "/v1/runtime/sandboxes",
        json={"agent_id": "double-term-agent", "profile_name": "micro"},
        headers=HEADERS,
    )
    sandbox_id = resp.json()["sandbox_id"]

    client.post(
        f"/v1/runtime/sandboxes/{sandbox_id}/terminate",
        json={"reason": "first_term"},
        headers=HEADERS,
    )

    resp = client.post(
        f"/v1/runtime/sandboxes/{sandbox_id}/terminate",
        json={"reason": "second_term"},
        headers=HEADERS,
    )
    assert resp.status_code == 400, resp.text
    print("PASS: double terminate rejected")


# ---- Logs and metrics ----


def test_sandbox_logs_recorded():
    """Sandbox lifecycle events produce logs."""
    resp = client.post(
        "/v1/runtime/sandboxes",
        json={"agent_id": "log-agent", "profile_name": "micro"},
        headers=HEADERS,
    )
    sandbox_id = resp.json()["sandbox_id"]

    resp = client.get(f"/v1/runtime/sandboxes/{sandbox_id}/logs", headers=HEADERS)
    assert resp.status_code == 200, resp.text
    logs = resp.json()["logs"]
    assert len(logs) >= 1  # At least provisioning log
    assert any("provisioned" in log["message"].lower() for log in logs)
    print("PASS: sandbox logs recorded")


def test_sandbox_metrics():
    """Can retrieve sandbox metrics."""
    resp = client.post(
        "/v1/runtime/sandboxes",
        json={"agent_id": "metric-agent", "profile_name": "micro"},
        headers=HEADERS,
    )
    sandbox_id = resp.json()["sandbox_id"]

    resp = client.get(f"/v1/runtime/sandboxes/{sandbox_id}/metrics", headers=HEADERS)
    assert resp.status_code == 200, resp.text
    assert "metrics" in resp.json()
    print("PASS: sandbox metrics")


# ---- List endpoints ----


def test_list_executions():
    """List executions with filters."""
    resp = client.get("/v1/runtime/executions", headers=HEADERS)
    assert resp.status_code == 200, resp.text
    assert "executions" in resp.json()
    assert "total" in resp.json()
    print("PASS: list executions")


def test_list_executions_by_agent():
    """Filter executions by agent_id."""
    resp = client.get(
        "/v1/runtime/executions?agent_id=lifecycle-agent", headers=HEADERS
    )
    assert resp.status_code == 200, resp.text
    for ex in resp.json()["executions"]:
        assert ex["agent_id"] == "lifecycle-agent"
    print("PASS: list executions by agent")


def test_sandbox_with_delegation_id():
    """Sandbox records delegation_id when provided."""
    resp = client.post(
        "/v1/runtime/sandboxes",
        json={
            "agent_id": "del-agent",
            "profile_name": "micro",
            "delegation_id": "del-12345",
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["delegation_id"] == "del-12345"
    print("PASS: sandbox with delegation_id")


def test_sandbox_with_lease_id():
    """Sandbox records lease_id when provided."""
    resp = client.post(
        "/v1/runtime/sandboxes",
        json={
            "agent_id": "lease-agent",
            "profile_name": "micro",
            "lease_id": "lease-67890",
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["lease_id"] == "lease-67890"
    print("PASS: sandbox with lease_id")


if __name__ == "__main__":
    test_create_sandbox_with_profile_name()
    test_create_sandbox_with_explicit_limits()
    test_create_sandbox_default_limits()
    test_get_sandbox()
    test_get_nonexistent_sandbox_404()
    test_full_execution_lifecycle()
    test_execution_with_failure()
    test_execute_non_ready_sandbox_rejected()
    test_terminate_ready_sandbox()
    test_terminate_executing_sandbox()
    test_terminate_already_terminated_rejected()
    test_sandbox_logs_recorded()
    test_sandbox_metrics()
    test_list_executions()
    test_list_executions_by_agent()
    test_sandbox_with_delegation_id()
    test_sandbox_with_lease_id()
    print("\nAll S80 tests passed!")
