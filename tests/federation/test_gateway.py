from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.cost_governance import storage as cost_storage


@pytest.fixture(autouse=True)
def isolate_federation_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    billing_db = tmp_path / "billing.db"
    monkeypatch.setenv(
        "AGENTHUB_API_KEYS_JSON",
        '{"dev-owner-key":"owner-dev","partner-owner-key":"owner-partner","platform-owner-key":"owner-platform"}',
    )
    monkeypatch.setenv("AGENTHUB_AUTH_TOKEN_SECRET", "test-federation-auth-secret")
    monkeypatch.setenv(
        "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON",
        '{"partner-east":"fed-partner-east-token","partner-west":"fed-partner-west-token"}',
    )
    monkeypatch.setenv("AGENTHUB_FEDERATION_AUDIT_PATH", str(tmp_path / "federation-audit.json"))
    monkeypatch.setenv("AGENTHUB_COST_EVENTS_PATH", str(tmp_path / "cost-events.json"))
    monkeypatch.setenv("AGENTHUB_COST_DB_PATH", str(billing_db))
    monkeypatch.setenv("AGENTHUB_BILLING_DB_PATH", str(billing_db))
    cost_storage.reset_for_tests(db_path=billing_db)


def test_federated_execution_requires_cross_boundary_auth() -> None:
    client = TestClient(app)
    denied = client.post(
        "/v1/federation/execute",
        json={
            "domain_id": "partner-east",
            "domain_token": "bad-token",
            "task_spec": "run remote task",
            "payload": {"input": "ok"},
            "policy_context": {"decision": "allow"},
            "estimated_cost_usd": 1.2,
            "max_budget_usd": 5.0,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s60-fed-denied-auth"},
    )
    assert denied.status_code == 403


def test_federated_execution_blocks_inline_secrets() -> None:
    client = TestClient(app)
    denied = client.post(
        "/v1/federation/execute",
        json={
            "domain_id": "partner-east",
            "domain_token": "fed-partner-east-token",
            "task_spec": "run remote task",
            "payload": {"api_key": "super-secret"},
            "policy_context": {"decision": "allow"},
            "estimated_cost_usd": 1.2,
            "max_budget_usd": 5.0,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s60-fed-inline-secret"},
    )
    assert denied.status_code == 400
    assert "inline secrets" in denied.json()["detail"]


def test_federated_execution_attestation_and_audit_completeness() -> None:
    client = TestClient(app)
    execute = client.post(
        "/v1/federation/execute",
        json={
            "domain_id": "partner-east",
            "domain_token": "fed-partner-east-token",
            "task_spec": "run remote task",
            "payload": {"input": "safe-data", "config_ref": "vault://cfg/abc"},
            "policy_context": {"decision": "allow", "policy_version": "runtime-policy-v2"},
            "estimated_cost_usd": 1.2,
            "max_budget_usd": 5.0,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s60-fed-success"},
    )
    assert execute.status_code == 200
    attestation = execute.json()["attestation"]
    assert attestation["attestation_hash"]
    assert attestation["input_hash"]
    assert attestation["output_hash"]

    audit = client.get("/v1/federation/audit", headers={"X-API-Key": "dev-owner-key"})
    assert audit.status_code == 200
    row = audit.json()["data"][0]
    for required in ["actor", "domain_id", "input_hash", "output_hash", "attestation_hash", "estimated_cost_usd", "timestamp"]:
        assert required in row
