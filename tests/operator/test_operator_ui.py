from __future__ import annotations

import uuid
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.store import STORE
from src.delegation import storage as delegation_storage

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def isolated_operator_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    registry_db = tmp_path / "registry.db"
    delegation_db = tmp_path / "delegation.db"
    monkeypatch.setenv("AGENTHUB_REGISTRY_DB_PATH", str(registry_db))
    monkeypatch.setenv("AGENTHUB_DELEGATION_DB_PATH", str(delegation_db))
    STORE.reset_for_tests(db_path=registry_db)
    delegation_storage.reset_for_tests(db_path=delegation_db)
    monkeypatch.setenv("AGENTHUB_EVAL_RESULTS_PATH", str(tmp_path / "evals.json"))


def _register_agent(client: TestClient) -> str:
    manifest = yaml.safe_load((ROOT / "seed" / "agents" / "data-normalizer.yaml").read_text(encoding="utf-8"))
    suffix = uuid.uuid4().hex[:8]
    manifest["identity"]["id"] = f"ops-agent-{suffix}"
    manifest["identity"]["name"] = f"Operator Agent {suffix}"
    namespace = f"@ops{suffix}"

    response = client.post(
        "/v1/agents",
        json={"namespace": namespace, "manifest": manifest},
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": f"s11-register-{suffix}"},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def test_operator_ui_journey_smoke_and_observability_sections() -> None:
    client = TestClient(app)
    agent_id = _register_agent(client)

    create = client.post(
        "/v1/delegations",
        json={
            "requester_agent_id": agent_id,
            "delegate_agent_id": agent_id,
            "task_spec": "Observe operator delegation status",
            "estimated_cost_usd": 2.0,
            "max_budget_usd": 5.0,
            "simulated_actual_cost_usd": 1.8,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s11-operator-delegation"},
    )
    assert create.status_code == 200, create.text
    delegation_id = create.json()["delegation_id"]

    ui = client.get("/operator")
    assert ui.status_code == 200
    assert "Operator Console" in ui.text

    dashboard = client.get(
        "/v1/operator/dashboard",
        params={"agent_id": agent_id, "query": "normalize records"},
        headers={"X-API-Key": "partner-owner-key", "X-Operator-Role": "viewer"},
    )
    assert dashboard.status_code == 200, dashboard.text
    payload = dashboard.json()
    assert payload["role"] == "viewer"
    assert set(payload["sections"].keys()) == {
        "search",
        "agent_detail",
        "eval",
        "trust",
        "delegations",
        "policy_cost_overlay",
        "timeline",
    }
    assert isinstance(payload["sections"]["search"]["results"], list)
    assert payload["sections"]["delegations"]
    assert payload["sections"]["policy_cost_overlay"]["totals"]["delegation_count"] >= 1
    assert payload["sections"]["timeline"]

    replay = client.get(
        f"/v1/operator/replay/{delegation_id}",
        headers={"X-API-Key": "partner-owner-key", "X-Operator-Role": "viewer"},
    )
    assert replay.status_code == 200
    replay_payload = replay.json()
    assert replay_payload["delegation_id"] == delegation_id
    assert replay_payload["timeline"]


def test_operator_role_boundaries_for_refresh_endpoint() -> None:
    client = TestClient(app)

    viewer = client.post(
        "/v1/operator/refresh",
        headers={"X-API-Key": "partner-owner-key", "X-Operator-Role": "viewer"},
    )
    assert viewer.status_code == 403

    elevate = client.post(
        "/v1/operator/refresh",
        headers={"X-API-Key": "partner-owner-key", "X-Operator-Role": "admin"},
    )
    assert elevate.status_code == 403

    admin = client.post(
        "/v1/operator/refresh",
        headers={"X-API-Key": "dev-owner-key", "X-Operator-Role": "admin"},
    )
    assert admin.status_code == 200
    assert admin.json()["status"] == "refreshed"


def test_operator_versioning_page_serves_compare_ui() -> None:
    client = TestClient(app)
    page = client.get("/operator/versioning")
    assert page.status_code == 200
    assert "Version Compare" in page.text
