from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from jsonschema import validate

from src.api.app import DELEGATION_IDEMPOTENCY_CACHE, app
from src.delegation import storage as delegation_storage

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "specs" / "delegation" / "delegation-contract-v2.schema.json"


@pytest.fixture(autouse=True)
def isolate_delegation_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "delegation.db"
    monkeypatch.setenv("AGENTHUB_DELEGATION_DB_PATH", str(db_path))
    delegation_storage.reset_for_tests(db_path=db_path)
    delegation_storage.save_balances(
        {
            "@demo:invoice-summarizer": 1000.0,
            "@demo:support-orchestrator": 1000.0,
        }
    )
    monkeypatch.setenv("AGENTHUB_TRUST_USAGE_EVENTS_PATH", str(tmp_path / "usage_events.json"))
    DELEGATION_IDEMPOTENCY_CACHE.clear()


def test_delegation_contract_endpoint_matches_schema() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    client = TestClient(app)
    response = client.get("/v1/delegations/contract", headers={"X-API-Key": "dev-owner-key"})
    assert response.status_code == 200
    payload = response.json()
    validate(instance=payload, schema=schema)


def test_delegation_response_includes_contract_snapshot() -> None:
    client = TestClient(app)
    response = client.post(
        "/v1/delegations",
        json={
            "requester_agent_id": "@demo:invoice-summarizer",
            "delegate_agent_id": "@demo:support-orchestrator",
            "task_spec": "Validate contract snapshot",
            "estimated_cost_usd": 5.0,
            "max_budget_usd": 10.0,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s19-contract-snapshot-1"},
    )
    assert response.status_code == 200
    assert response.json()["contract"]["version"] == "delegation-contract-v2"
