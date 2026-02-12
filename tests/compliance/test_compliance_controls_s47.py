from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.cost_governance import storage as cost_storage


@pytest.fixture(autouse=True)
def isolate_compliance_dependencies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    billing_db = tmp_path / "billing.db"
    monkeypatch.setenv("AGENTHUB_BILLING_DB_PATH", str(billing_db))
    monkeypatch.setenv("AGENTHUB_COST_DB_PATH", str(billing_db))
    monkeypatch.setenv("AGENTHUB_COST_EVENTS_PATH", str(tmp_path / "cost-events.json"))
    monkeypatch.setenv("AGENTHUB_FEDERATION_AUDIT_PATH", str(tmp_path / "federation-audit.json"))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_POLICY_PACKS_PATH", str(tmp_path / "proc-policy-packs.json"))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_APPROVALS_PATH", str(tmp_path / "proc-approvals.json"))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_EXCEPTIONS_PATH", str(tmp_path / "proc-exceptions.json"))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_AUDIT_PATH", str(tmp_path / "proc-audit.json"))
    monkeypatch.setenv("AGENTHUB_COMPLIANCE_EVIDENCE_PATH", str(tmp_path / "compliance-reports.json"))
    cost_storage.reset_for_tests(db_path=billing_db)


def _seed_control_artifacts(client: TestClient) -> None:
    subscription = client.post(
        "/v1/billing/subscriptions",
        json={"account_id": "acct-enterprise", "plan_id": "pro", "monthly_fee_usd": 99.0, "included_units": 1000},
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert subscription.status_code == 200

    usage = client.post(
        "/v1/billing/usage",
        json={"account_id": "acct-enterprise", "meter": "delegation.compute", "quantity": 12, "unit_price_usd": 0.25},
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert usage.status_code == 200

    invoice = client.post(
        "/v1/billing/invoices/generate",
        json={"account_id": "acct-enterprise"},
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert invoice.status_code == 200

    procurement = client.post(
        "/v1/procurement/policy-packs",
        json={
            "buyer": "owner-partner",
            "auto_approve_limit_usd": 1.0,
            "hard_stop_limit_usd": 5.0,
            "allowed_sellers": ["owner-dev"],
        },
        headers={"X-API-Key": "platform-owner-key"},
    )
    assert procurement.status_code == 200

    federation = client.post(
        "/v1/federation/execute",
        json={
            "domain_id": "partner-east",
            "domain_token": "fed-partner-east-token",
            "task_spec": "compliance seed",
            "payload": {"input": "safe"},
            "policy_context": {"decision": "allow", "policy_version": "runtime-policy-v3"},
            "estimated_cost_usd": 0.8,
            "max_budget_usd": 2.0,
            "connection_mode": "public_internet",
            "requested_residency_region": "us-east",
        },
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert federation.status_code == 200


def test_compliance_export_generates_soc2_control_evidence_bundle() -> None:
    client = TestClient(app)
    _seed_control_artifacts(client)

    controls = client.get("/v1/compliance/controls", params={"framework": "SOC2"}, headers={"X-API-Key": "dev-owner-key"})
    assert controls.status_code == 200
    assert len(controls.json()["data"]) >= 3

    exported = client.post(
        "/v1/compliance/evidence/export",
        json={"framework": "SOC2"},
        headers={"X-API-Key": "platform-owner-key"},
    )
    assert exported.status_code == 200, exported.text
    payload = exported.json()
    assert payload["framework"] == "SOC2"
    assert payload["summary"]["control_count"] >= 3
    assert payload["summary"]["failed_count"] == 0
    assert payload["report_id"]

    reports = client.get(
        "/v1/compliance/evidence",
        params={"framework": "SOC2", "limit": 10},
        headers={"X-API-Key": "platform-owner-key"},
    )
    assert reports.status_code == 200
    assert reports.json()["data"][0]["report_id"] == payload["report_id"]


def test_compliance_evidence_endpoints_enforce_admin_boundary() -> None:
    client = TestClient(app)
    denied_export = client.post(
        "/v1/compliance/evidence/export",
        json={"framework": "SOC2"},
        headers={"X-API-Key": "partner-owner-key"},
    )
    assert denied_export.status_code == 403

    denied_list = client.get("/v1/compliance/evidence", headers={"X-API-Key": "partner-owner-key"})
    assert denied_list.status_code == 403


def test_compliance_export_surfaces_control_failures_for_malformed_evidence() -> None:
    client = TestClient(app)
    audit_path = Path(os.environ["AGENTHUB_FEDERATION_AUDIT_PATH"])
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_path.write_text(json.dumps([{"timestamp": "2026-02-12T00:00:00Z", "domain_id": "partner-east"}]) + "\n", encoding="utf-8")

    exported = client.post(
        "/v1/compliance/evidence/export",
        json={"framework": "ISO27001"},
        headers={"X-API-Key": "platform-owner-key"},
    )
    assert exported.status_code == 200
    payload = exported.json()
    assert payload["summary"]["failed_count"] >= 1
    failed = [row for row in payload["controls"] if row["status"] == "fail"]
    assert any(row["check_key"] == "federation_audit_completeness" for row in failed)
