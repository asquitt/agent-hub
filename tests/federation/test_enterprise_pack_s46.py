from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.cost_governance import storage as cost_storage


@pytest.fixture(autouse=True)
def isolate_federation_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    billing_db = tmp_path / "billing.db"
    monkeypatch.setenv("AGENTHUB_FEDERATION_AUDIT_PATH", str(tmp_path / "federation-audit.json"))
    monkeypatch.setenv("AGENTHUB_COST_EVENTS_PATH", str(tmp_path / "cost-events.json"))
    monkeypatch.setenv("AGENTHUB_COST_DB_PATH", str(billing_db))
    monkeypatch.setenv("AGENTHUB_BILLING_DB_PATH", str(billing_db))
    cost_storage.reset_for_tests(db_path=billing_db)


def _execute_federated(client: TestClient, **overrides: object):
    payload = {
        "domain_id": "partner-east",
        "domain_token": "fed-partner-east-token",
        "task_spec": "run remote task",
        "payload": {"input": "safe-data", "config_ref": "vault://cfg/abc"},
        "policy_context": {"decision": "allow", "policy_version": "runtime-policy-v3"},
        "estimated_cost_usd": 1.2,
        "max_budget_usd": 5.0,
        "connection_mode": "public_internet",
    }
    payload.update(overrides)
    return client.post("/v1/federation/execute", json=payload, headers={"X-API-Key": "dev-owner-key"})


def test_federation_enterprise_boundary_private_connect_and_residency() -> None:
    client = TestClient(app)

    denied_public = _execute_federated(
        client,
        domain_id="partner-west",
        domain_token="fed-partner-west-token",
        connection_mode="public_internet",
    )
    assert denied_public.status_code == 403
    assert "private connectivity required" in denied_public.json()["detail"]

    denied_residency = _execute_federated(
        client,
        domain_id="partner-west",
        domain_token="fed-partner-west-token",
        connection_mode="private_connect",
        requested_residency_region="us-east",
    )
    assert denied_residency.status_code == 403
    assert "residency region" in denied_residency.json()["detail"]

    allowed = _execute_federated(
        client,
        domain_id="partner-west",
        domain_token="fed-partner-west-token",
        connection_mode="private_connect",
        requested_residency_region="us-west",
    )
    assert allowed.status_code == 200, allowed.text
    attestation = allowed.json()["attestation"]
    assert attestation["residency_region"] == "us-west"
    assert attestation["connection_mode"] == "private_connect"


def test_federation_domains_endpoint_exposes_enterprise_profiles() -> None:
    client = TestClient(app)
    response = client.get("/v1/federation/domains", headers={"X-API-Key": "dev-owner-key"})
    assert response.status_code == 200
    profiles = {row["domain_id"]: row for row in response.json()["data"]}
    assert profiles["partner-east"]["residency_region"] == "us-east"
    assert profiles["partner-west"]["private_connect_required"] is True
    assert profiles["partner-west"]["network_pattern"] == "private-connect"


def test_federation_attestation_export_requires_admin_and_returns_bundle() -> None:
    client = TestClient(app)
    executed = _execute_federated(client)
    assert executed.status_code == 200

    denied = client.get(
        "/v1/federation/attestations/export",
        params={"domain_id": "partner-east", "limit": 10},
        headers={"X-API-Key": "partner-owner-key"},
    )
    assert denied.status_code == 403

    exported = client.get(
        "/v1/federation/attestations/export",
        params={"domain_id": "partner-east", "limit": 10},
        headers={"X-API-Key": "platform-owner-key"},
    )
    assert exported.status_code == 200, exported.text
    payload = exported.json()
    assert payload["manifest"]["record_count"] >= 1
    assert payload["manifest"]["bundle_hash"]
    first = payload["records"][0]
    assert first["domain_id"] == "partner-east"
    assert first["residency_region"] == "us-east"
    assert first["connection_mode"] == "public_internet"
