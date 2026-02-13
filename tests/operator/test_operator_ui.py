from __future__ import annotations

import uuid
import warnings
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


def test_operator_startup_diagnostics_requires_admin_role() -> None:
    client = TestClient(app)

    viewer = client.get(
        "/v1/operator/startup-diagnostics",
        headers={"X-API-Key": "dev-owner-key", "X-Operator-Role": "viewer"},
    )
    assert viewer.status_code == 403

    admin = client.get(
        "/v1/operator/startup-diagnostics",
        headers={"X-API-Key": "dev-owner-key", "X-Operator-Role": "admin"},
    )
    assert admin.status_code == 200, admin.text
    payload = admin.json()
    assert payload["role"] == "admin"
    assert "checks" in payload
    assert "probes" in payload
    assert "overall_ready" in payload


def test_operator_startup_diagnostics_failing_only_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_REGISTRY_DB_PATH", "/dev/null/registry.db")
    client = TestClient(app)
    response = client.get(
        "/v1/operator/startup-diagnostics",
        params={"failing_only": "true"},
        headers={"X-API-Key": "dev-owner-key", "X-Operator-Role": "admin"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["checks"] == []
    assert payload["probes"]
    assert all(row["status"] == "fail" for row in payload["probes"])


def test_operator_versioning_page_serves_compare_ui() -> None:
    client = TestClient(app)
    page = client.get("/operator/versioning")
    assert page.status_code == 200
    assert "Version Compare" in page.text
    assert "Load Latest Pair" in page.text
    assert 'placeholder="@namespace:agent-id"' in page.text
    assert 'value="@demo:invoice-summarizer"' not in page.text


def test_operator_page_prompts_for_agent_id_instead_of_hardcoded_seed() -> None:
    client = TestClient(app)
    page = client.get("/operator")
    assert page.status_code == 200
    assert 'placeholder="@namespace:agent-id"' in page.text
    assert 'value="@seed:pipeline-planner"' not in page.text
    assert "Register an agent with `POST /v1/agents`" in page.text


def test_customer_journey_page_returns_404_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTHUB_CUSTOMER_UI_ENABLED", raising=False)
    monkeypatch.delenv("AGENTHUB_CUSTOMER_UI_REQUIRE_AUTH", raising=False)
    monkeypatch.delenv("AGENTHUB_CUSTOMER_UI_ALLOWED_OWNERS_JSON", raising=False)
    client = TestClient(app)
    page = client.get("/customer", headers={"X-API-Key": "dev-owner-key"})
    assert page.status_code == 404


def test_customer_journey_requires_auth_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_CUSTOMER_UI_ENABLED", "true")
    monkeypatch.setenv("AGENTHUB_CUSTOMER_UI_REQUIRE_AUTH", "true")
    monkeypatch.setenv("AGENTHUB_CUSTOMER_UI_ALLOWED_OWNERS_JSON", '["owner-dev","owner-platform"]')
    client = TestClient(app)
    page = client.get("/customer")
    assert page.status_code == 401


def test_customer_journey_rejects_owner_not_allowlisted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_CUSTOMER_UI_ENABLED", "true")
    monkeypatch.setenv("AGENTHUB_CUSTOMER_UI_REQUIRE_AUTH", "true")
    monkeypatch.setenv("AGENTHUB_CUSTOMER_UI_ALLOWED_OWNERS_JSON", '["owner-dev"]')
    client = TestClient(app)
    page = client.get("/customer", headers={"X-API-Key": "partner-owner-key"})
    assert page.status_code == 403


def test_customer_journey_page_serves_for_authorized_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_CUSTOMER_UI_ENABLED", "true")
    monkeypatch.setenv("AGENTHUB_CUSTOMER_UI_REQUIRE_AUTH", "true")
    monkeypatch.setenv("AGENTHUB_CUSTOMER_UI_ALLOWED_OWNERS_JSON", '["owner-dev","owner-platform"]')
    client = TestClient(app)
    page = client.get("/customer", headers={"X-API-Key": "dev-owner-key"})
    assert page.status_code == 200
    assert "Customer Journey Console" in page.text
    assert "Run Full Demo" in page.text
    assert 'id="sellerKey" value=""' in page.text
    assert 'id="buyerKey" value=""' in page.text
    assert 'id="adminKey" value=""' in page.text
    assert "dev-owner-key" not in page.text
    assert "partner-owner-key" not in page.text
    assert "platform-owner-key" not in page.text


def test_lifespan_startup_passes_with_valid_enforce_auth_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "enforce")
    monkeypatch.setenv(
        "AGENTHUB_API_KEYS_JSON",
        '{"dev-owner-key":"owner-dev","partner-owner-key":"owner-partner","platform-owner-key":"owner-platform"}',
    )
    monkeypatch.setenv("AGENTHUB_AUTH_TOKEN_SECRET", "s58-startup-secret")
    with TestClient(app) as client:
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


def test_lifespan_startup_fails_without_required_enforce_auth_envs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "enforce")
    monkeypatch.delenv("AGENTHUB_API_KEYS_JSON", raising=False)
    monkeypatch.delenv("AGENTHUB_AUTH_TOKEN_SECRET", raising=False)

    with pytest.raises(RuntimeError, match="AGENTHUB_API_KEYS_JSON is required"):
        with TestClient(app):
            pass


def test_startup_has_no_on_event_deprecation_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "enforce")
    monkeypatch.setenv(
        "AGENTHUB_API_KEYS_JSON",
        '{"dev-owner-key":"owner-dev","partner-owner-key":"owner-partner","platform-owner-key":"owner-platform"}',
    )
    monkeypatch.setenv("AGENTHUB_AUTH_TOKEN_SECRET", "s58-warning-check-secret")

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always", DeprecationWarning)
        with TestClient(app) as client:
            response = client.get("/healthz")
            assert response.status_code == 200

    on_event_warnings = [item for item in captured if "on_event" in str(item.message)]
    assert on_event_warnings == []
