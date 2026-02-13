from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.store import STORE


ROOT = Path(__file__).resolve().parents[2]
VALID_MANIFEST_PATH = ROOT / "specs" / "manifest" / "examples" / "simple-tool-agent.yaml"


def _manifest(slug: str = "invoice-summarizer", version: str = "1.0.0") -> dict[str, object]:
    payload = yaml.safe_load(VALID_MANIFEST_PATH.read_text(encoding="utf-8"))
    payload["identity"]["id"] = slug
    payload["identity"]["version"] = version
    return payload


@pytest.fixture()
def enforce_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    registry_db = tmp_path / "registry.db"
    monkeypatch.setenv("AGENTHUB_REGISTRY_DB_PATH", str(registry_db))
    STORE.reset_for_tests(db_path=registry_db)
    monkeypatch.setenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "enforce")
    monkeypatch.setenv(
        "AGENTHUB_API_KEYS_JSON",
        '{"dev-owner-key":"owner-dev","partner-owner-key":"owner-partner","platform-owner-key":"owner-platform"}',
    )
    monkeypatch.setenv("AGENTHUB_AUTH_TOKEN_SECRET", "test-token-secret-s53")
    monkeypatch.setenv(
        "AGENTHUB_OWNER_TENANTS_JSON",
        '{"owner-dev":["*"],"owner-platform":["*"],"owner-partner":["tenant-partner"]}',
    )
    monkeypatch.setenv("AGENTHUB_EVAL_RESULTS_PATH", str(tmp_path / "results.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_USAGE_EVENTS_PATH", str(tmp_path / "usage_events.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_REVIEWS_PATH", str(tmp_path / "reviews.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_SECURITY_AUDITS_PATH", str(tmp_path / "security_audits.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_INCIDENTS_PATH", str(tmp_path / "incidents.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_PUBLISHER_PROFILES_PATH", str(tmp_path / "publisher_profiles.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_SCORES_PATH", str(tmp_path / "scores.json"))


def _register_agent(client: TestClient, *, tenant_id: str = "tenant-a") -> str:
    response = client.post(
        "/v1/agents",
        json={"namespace": "@secure", "manifest": _manifest()},
        headers={
            "X-API-Key": "dev-owner-key",
            "X-Tenant-ID": tenant_id,
            "Idempotency-Key": "s53-register-agent",
        },
    )
    assert response.status_code == 200, response.text
    return str(response.json()["id"])


def test_enforce_mode_blocks_unauthenticated_tenant_route(enforce_runtime: None) -> None:
    with TestClient(app) as client:
        agent_id = _register_agent(client)
        response = client.get(f"/v1/agents/{agent_id}", headers={"X-Tenant-ID": "tenant-a"})
        assert response.status_code == 401
        assert response.json()["detail"]["code"] == "auth.required"


def test_enforce_mode_blocks_spoofed_tenant_claim(enforce_runtime: None) -> None:
    with TestClient(app) as client:
        agent_id = _register_agent(client)
        response = client.get(
            f"/v1/agents/{agent_id}",
            headers={"X-API-Key": "partner-owner-key", "X-Tenant-ID": "tenant-a"},
        )
        assert response.status_code == 403
        assert response.json()["detail"]["code"] == "tenant.forbidden"


def test_enforce_mode_allows_authorized_tenant_access(enforce_runtime: None) -> None:
    with TestClient(app) as client:
        agent_id = _register_agent(client)
        response = client.get(
            f"/v1/agents/{agent_id}",
            headers={"X-API-Key": "dev-owner-key", "X-Tenant-ID": "tenant-a"},
        )
        assert response.status_code == 200


def test_enforce_mode_requires_idempotency_key_for_mutations(enforce_runtime: None) -> None:
    with TestClient(app) as client:
        response = client.post(
            "/v1/billing/subscriptions",
            json={"account_id": "acct-1", "plan_id": "basic", "monthly_fee_usd": 10, "included_units": 100},
            headers={"X-API-Key": "dev-owner-key"},
        )
        assert response.status_code == 400
        assert response.json()["detail"]["code"] == "idempotency.missing_key"


def test_persistent_idempotency_replays_identical_mutation_response(enforce_runtime: None) -> None:
    payload = {"account_id": "acct-1", "plan_id": "basic", "monthly_fee_usd": 10, "included_units": 100}
    headers = {"X-API-Key": "dev-owner-key", "Idempotency-Key": "s53-idempotent-subscription"}
    with TestClient(app) as client:
        first = client.post("/v1/billing/subscriptions", json=payload, headers=headers)
        second = client.post("/v1/billing/subscriptions", json=payload, headers=headers)
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()
    assert second.headers.get("X-AgentHub-Idempotent-Replay") == "true"


def test_persistent_idempotency_rejects_key_reuse_with_different_payload(enforce_runtime: None) -> None:
    with TestClient(app) as client:
        first = client.post(
            "/v1/billing/subscriptions",
            json={"account_id": "acct-1", "plan_id": "basic", "monthly_fee_usd": 10, "included_units": 100},
            headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s53-idempotent-conflict"},
        )
        second = client.post(
            "/v1/billing/subscriptions",
            json={"account_id": "acct-1", "plan_id": "plus", "monthly_fee_usd": 25, "included_units": 100},
            headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s53-idempotent-conflict"},
        )
    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "idempotency.key_reused_with_different_payload"


def test_warn_mode_allows_missing_idempotency_key_with_warning(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    registry_db = tmp_path / "registry.db"
    monkeypatch.setenv("AGENTHUB_REGISTRY_DB_PATH", str(registry_db))
    STORE.reset_for_tests(db_path=registry_db)
    monkeypatch.setenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "warn")
    with TestClient(app) as client:
        response = client.post(
            "/v1/billing/subscriptions",
            json={"account_id": "acct-1", "plan_id": "basic", "monthly_fee_usd": 10, "included_units": 100},
            headers={"X-API-Key": "dev-owner-key"},
        )
    assert response.status_code == 200
    warn = response.headers.get("X-AgentHub-Deprecation-Warn", "")
    assert "idempotency.missing_key" in warn
