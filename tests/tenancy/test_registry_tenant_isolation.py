from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.store import STORE

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "specs" / "manifest" / "examples" / "simple-tool-agent.yaml"


@pytest.fixture(autouse=True)
def isolate_registry_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    registry_db = tmp_path / "registry.db"
    monkeypatch.setenv("AGENTHUB_REGISTRY_DB_PATH", str(registry_db))
    STORE.reset_for_tests(db_path=registry_db)
    monkeypatch.setenv("AGENTHUB_EVAL_RESULTS_PATH", str(tmp_path / "evals.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_USAGE_EVENTS_PATH", str(tmp_path / "usage.json"))


def _manifest(slug: str, version: str = "1.0.0") -> dict:
    row = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
    row["identity"]["id"] = slug
    row["identity"]["version"] = version
    row["identity"]["name"] = f"{slug}-name"
    return row


def test_cross_tenant_access_denied_for_get_update_delete() -> None:
    client = TestClient(app)
    create = client.post(
        "/v1/agents",
        json={"namespace": "@tenanta", "manifest": _manifest("tenant-a-agent")},
        headers={
            "X-API-Key": "dev-owner-key",
            "Idempotency-Key": "s31-create-a",
            "X-Tenant-ID": "tenant-a",
        },
    )
    assert create.status_code == 200, create.text
    agent_id = create.json()["id"]

    list_a = client.get("/v1/agents", headers={"X-Tenant-ID": "tenant-a"})
    list_b = client.get("/v1/agents", headers={"X-Tenant-ID": "tenant-b"})
    assert any(row["id"] == agent_id for row in list_a.json()["data"])
    assert all(row["id"] != agent_id for row in list_b.json()["data"])

    get_wrong_tenant = client.get(f"/v1/agents/{agent_id}", headers={"X-Tenant-ID": "tenant-b"})
    assert get_wrong_tenant.status_code == 404

    update_wrong_tenant = client.put(
        f"/v1/agents/{agent_id}",
        json={"manifest": _manifest("tenant-a-agent", version="1.0.1")},
        headers={
            "X-API-Key": "dev-owner-key",
            "Idempotency-Key": "s31-update-wrong-tenant",
            "X-Tenant-ID": "tenant-b",
        },
    )
    assert update_wrong_tenant.status_code == 404

    delete_wrong_tenant = client.delete(
        f"/v1/agents/{agent_id}",
        headers={
            "X-API-Key": "dev-owner-key",
            "Idempotency-Key": "s31-delete-wrong-tenant",
            "X-Tenant-ID": "tenant-b",
        },
    )
    assert delete_wrong_tenant.status_code == 404


def test_namespace_listing_is_tenant_scoped() -> None:
    client = TestClient(app)

    create_a = client.post(
        "/v1/agents",
        json={"namespace": "@scopea", "manifest": _manifest("scope-agent-a")},
        headers={
            "X-API-Key": "dev-owner-key",
            "Idempotency-Key": "s31-namespace-a",
            "X-Tenant-ID": "tenant-a",
        },
    )
    assert create_a.status_code == 200

    create_b = client.post(
        "/v1/agents",
        json={"namespace": "@scopeb", "manifest": _manifest("scope-agent-b")},
        headers={
            "X-API-Key": "dev-owner-key",
            "Idempotency-Key": "s31-namespace-b",
            "X-Tenant-ID": "tenant-b",
        },
    )
    assert create_b.status_code == 200

    ns_a_as_a = client.get("/v1/namespaces/@scopea", headers={"X-Tenant-ID": "tenant-a"})
    ns_a_as_b = client.get("/v1/namespaces/@scopea", headers={"X-Tenant-ID": "tenant-b"})
    assert ns_a_as_a.status_code == 200
    assert len(ns_a_as_a.json()["data"]) == 1
    assert ns_a_as_b.status_code == 200
    assert ns_a_as_b.json()["data"] == []
