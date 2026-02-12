from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.store import STORE
from src.discovery.service import DISCOVERY_SERVICE

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "specs" / "manifest" / "examples" / "simple-tool-agent.yaml"


@pytest.fixture(autouse=True)
def isolate_registry_and_discovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    registry_db = tmp_path / "registry.db"
    monkeypatch.setenv("AGENTHUB_REGISTRY_DB_PATH", str(registry_db))
    STORE.reset_for_tests(db_path=registry_db)
    monkeypatch.setenv("AGENTHUB_EVAL_RESULTS_PATH", str(tmp_path / "evals.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_USAGE_EVENTS_PATH", str(tmp_path / "trust-usage.json"))
    DISCOVERY_SERVICE.refresh_index(force=True)


def _manifest(slug: str, capability_id: str, capability_name: str, description: str) -> dict:
    manifest = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
    manifest["identity"]["id"] = slug
    manifest["identity"]["name"] = f"{slug}-name"
    cap = manifest["capabilities"][0]
    cap["id"] = capability_id
    cap["name"] = capability_name
    cap["description"] = description
    cap["input_schema"]["required"] = ["live_payload"]
    cap["output_schema"]["required"] = ["live_result"]
    return manifest


def test_registry_manifest_is_indexed_for_semantic_discovery() -> None:
    client = TestClient(app)
    response = client.post(
        "/v1/agents",
        json={
            "namespace": "@liveindex",
            "manifest": _manifest(
                slug="live-index-agent",
                capability_id="live-registry-search",
                capability_name="Live Registry Search",
                description="Discover ultra live indexed capability results from registry data.",
            ),
        },
        headers={
            "X-API-Key": "dev-owner-key",
            "Idempotency-Key": "s34-live-index-1",
        },
    )
    assert response.status_code == 200, response.text

    DISCOVERY_SERVICE.refresh_index(force=True)
    result = client.post(
        "/v1/discovery/search",
        json={"query": "ultra live indexed capability", "constraints": {"max_cost_usd": 1.0}},
    )
    assert result.status_code == 200
    payload = result.json()
    assert any(item["capability_id"] == "live-registry-search" for item in payload["data"])
    assert any(item["source"] == "registry" for item in payload["data"])


def test_refresh_index_brings_new_registry_capability_into_contract_match() -> None:
    client = TestClient(app)
    create = client.post(
        "/v1/agents",
        json={
            "namespace": "@contracts34",
            "manifest": _manifest(
                slug="contract-live-agent",
                capability_id="contract-live-capability",
                capability_name="Contract Live Capability",
                description="Provides contract live matching from registry-backed index.",
            ),
        },
        headers={
            "X-API-Key": "dev-owner-key",
            "Idempotency-Key": "s34-live-index-2",
        },
    )
    assert create.status_code == 200

    DISCOVERY_SERVICE.refresh_index(force=True)
    match = client.post(
        "/v1/discovery/contract-match",
        json={
            "input_schema": {"type": "object", "required": ["live_payload"]},
            "output_schema": {"type": "object", "required": ["live_result"]},
            "constraints": {"max_cost_usd": 1.0},
        },
    )
    assert match.status_code == 200
    rows = match.json()["data"]
    assert any(row["capability_id"] == "contract-live-capability" for row in rows)
