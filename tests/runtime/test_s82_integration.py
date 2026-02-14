"""S82: Integration — delegation, lease, compliance, audit evidence."""

from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key-001": "test-owner"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-signing-secret-s82")

from starlette.testclient import TestClient

from src.api.app import app
from src.runtime.storage import reset_for_tests

HEADERS = {"X-API-Key": "test-key-001"}

client = TestClient(app)
reset_for_tests()


# ---- Delegation → Sandbox integration ----


def test_delegation_creates_runtime_sandbox():
    """Delegation service uses runtime sandbox when available."""
    from src.delegation import storage as delegation_storage

    delegation_storage.save_balances({"agent-req": 1000.0})

    from src.delegation.service import create_delegation

    result = create_delegation(
        requester_agent_id="agent-req",
        delegate_agent_id="agent-del",
        task_spec="test-task",
        estimated_cost_usd=10.0,
        max_budget_usd=50.0,
    )
    assert result["delegation_id"]
    assert result["status"] in ("completed", "pending_reauthorization", "failed_hard_stop")
    # The lifecycle should include an execution stage with a sandbox_id
    exec_stages = [s for s in result["lifecycle"] if s["stage"] == "execution"]
    assert len(exec_stages) == 1
    assert exec_stages[0]["details"].get("sandbox_id", "").startswith("sbx-")
    print("PASS: delegation creates runtime sandbox")


# ---- Delegated sandbox endpoint ----


def test_delegated_sandbox_missing_delegation_404():
    """Creating a delegated sandbox with nonexistent delegation returns 404."""
    resp = client.post(
        "/v1/runtime/sandboxes/delegated",
        json={"delegation_id": "nonexistent", "agent_id": "agent-x"},
        headers=HEADERS,
    )
    assert resp.status_code == 404, resp.text
    print("PASS: delegated sandbox missing delegation 404")


def test_delegated_sandbox_success():
    """Create a sandbox linked to a delegation."""
    from src.delegation import storage as delegation_storage

    delegation_storage.save_balances({"agent-d1": 1000.0})

    from src.delegation.service import create_delegation

    d = create_delegation(
        requester_agent_id="agent-d1",
        delegate_agent_id="agent-d2",
        task_spec="sandboxed",
        estimated_cost_usd=5.0,
        max_budget_usd=50.0,
    )
    resp = client.post(
        "/v1/runtime/sandboxes/delegated",
        json={"delegation_id": d["delegation_id"], "agent_id": "agent-d2"},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["sandbox_id"].startswith("sbx-")
    assert data["delegation_id"] == d["delegation_id"]
    assert data["status"] == "ready"
    print("PASS: delegated sandbox success")


# ---- Leased sandbox endpoint ----


def test_leased_sandbox_missing_lease_404():
    """Creating a leased sandbox with nonexistent lease returns 404."""
    resp = client.post(
        "/v1/runtime/sandboxes/leased",
        json={"lease_id": "nonexistent", "agent_id": "agent-x"},
        headers=HEADERS,
    )
    assert resp.status_code in (404, 400), resp.text
    print("PASS: leased sandbox missing lease 404")


def test_leased_sandbox_success():
    """Create a sandbox linked to an active lease."""
    from src.lease.service import create_lease

    lease = create_lease(
        requester_agent_id="agent-lease",
        capability_ref="cap:compute",
        owner="test-owner",
        ttl_seconds=3600,
    )
    resp = client.post(
        "/v1/runtime/sandboxes/leased",
        json={"lease_id": lease["lease_id"], "agent_id": "agent-lease"},
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["sandbox_id"].startswith("sbx-")
    assert data["lease_id"] == lease["lease_id"]
    assert data["status"] == "ready"
    print("PASS: leased sandbox success")


# ---- Audit evidence endpoint ----


def test_audit_evidence_returns_data():
    """Audit evidence endpoint returns sandboxes and executions."""
    # Create a sandbox and run an execution first
    resp = client.post(
        "/v1/runtime/sandboxes",
        json={"agent_id": "audit-agent", "profile_name": "micro"},
        headers=HEADERS,
    )
    sandbox_id = resp.json()["sandbox_id"]

    resp = client.post(
        f"/v1/runtime/sandboxes/{sandbox_id}/execute",
        json={"input_data": {"task": "audit-test"}},
        headers=HEADERS,
    )
    assert resp.status_code == 200

    resp = client.post(
        f"/v1/runtime/sandboxes/{sandbox_id}/complete",
        json={"exit_code": 0, "output_data": {"result": "ok"}},
        headers=HEADERS,
    )
    assert resp.status_code == 200

    resp = client.get("/v1/runtime/audit/evidence", headers=HEADERS)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["sandbox_count"] >= 1
    assert data["execution_count"] >= 1
    assert data["generated_by"] == "test-owner"
    print("PASS: audit evidence returns data")


def test_audit_evidence_filter_by_agent():
    """Audit evidence can filter by agent_id."""
    resp = client.get(
        "/v1/runtime/audit/evidence?agent_id=audit-agent", headers=HEADERS
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    for sbx in data["sandboxes"]:
        assert sbx["agent_id"] == "audit-agent"
    print("PASS: audit evidence filter by agent")


# ---- Compliance integration ----


def test_compliance_sandbox_controls_listed():
    """Compliance controls include sandbox audit entries."""
    from src.compliance.service import list_controls

    soc2_controls = list_controls(framework="SOC2")
    check_keys = {c["check_key"] for c in soc2_controls}
    assert "sandbox_audit_completeness" in check_keys

    iso_controls = list_controls(framework="ISO27001")
    check_keys = {c["check_key"] for c in iso_controls}
    assert "sandbox_audit_completeness" in check_keys
    print("PASS: compliance sandbox controls listed")


def test_compliance_sandbox_check_runs():
    """Sandbox audit completeness check executes without error."""
    from src.compliance.service import CHECKS

    result = CHECKS["sandbox_audit_completeness"]()
    assert "passed" in result
    assert "evidence" in result
    assert result["evidence"]["execution_count"] >= 0
    print("PASS: compliance sandbox check runs")


def test_compliance_evidence_export_includes_sandbox():
    """Full compliance evidence export includes sandbox controls."""
    from src.compliance.service import export_evidence_pack

    report = export_evidence_pack(
        actor="test-owner",
        framework="SOC2",
        control_ids=["SOC2-CC7.4"],
    )
    assert report["summary"]["control_count"] == 1
    ctrl = report["controls"][0]
    assert ctrl["control_id"] == "SOC2-CC7.4"
    assert ctrl["check_key"] == "sandbox_audit_completeness"
    assert ctrl["status"] in ("pass", "fail")
    print("PASS: compliance evidence export includes sandbox")


# ---- End-to-end flow ----


def test_end_to_end_delegation_sandbox_audit():
    """End-to-end: delegation → sandbox → execution → audit evidence."""
    from src.delegation import storage as delegation_storage

    delegation_storage.save_balances({"e2e-req": 1000.0})

    from src.delegation.service import create_delegation

    d = create_delegation(
        requester_agent_id="e2e-req",
        delegate_agent_id="e2e-del",
        task_spec="e2e-task",
        estimated_cost_usd=5.0,
        max_budget_usd=50.0,
    )
    assert d["delegation_id"]

    resp = client.get(
        f"/v1/runtime/audit/evidence?agent_id=e2e-del", headers=HEADERS
    )
    assert resp.status_code == 200
    # The delegation should have created a sandbox for e2e-del
    data = resp.json()
    del_sandboxes = [s for s in data["sandboxes"] if s["agent_id"] == "e2e-del"]
    assert len(del_sandboxes) >= 1
    print("PASS: end-to-end delegation → sandbox → audit")


if __name__ == "__main__":
    test_delegation_creates_runtime_sandbox()
    test_delegated_sandbox_missing_delegation_404()
    test_delegated_sandbox_success()
    test_leased_sandbox_missing_lease_404()
    test_leased_sandbox_success()
    test_audit_evidence_returns_data()
    test_audit_evidence_filter_by_agent()
    test_compliance_sandbox_controls_listed()
    test_compliance_sandbox_check_runs()
    test_compliance_evidence_export_includes_sandbox()
    test_end_to_end_delegation_sandbox_audit()
    print("\nAll S82 tests passed!")
