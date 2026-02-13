from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.store import STORE
from src.versioning import compute_behavioral_diff

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "specs" / "manifest" / "examples" / "simple-tool-agent.yaml"


@pytest.fixture(autouse=True)
def reset_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    registry_db = tmp_path / "registry.db"
    monkeypatch.setenv("AGENTHUB_REGISTRY_DB_PATH", str(registry_db))
    STORE.reset_for_tests(db_path=registry_db)
    monkeypatch.setenv("AGENTHUB_EVAL_RESULTS_PATH", str(tmp_path / "evals.json"))


def _manifest(version: str) -> dict:
    loaded = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    loaded["identity"]["version"] = version
    return loaded


def test_compute_behavioral_diff_detects_breaking_changes() -> None:
    base = _manifest("1.0.0")
    target = _manifest("1.1.0")

    capability = target["capabilities"][0]
    capability["input_schema"]["required"].append("currency")
    capability["output_schema"]["required"].remove("vendor")
    capability["protocols"] = ["MCP"]
    capability["side_effect_level"] = "low"
    capability["idempotency_key_required"] = True

    diff = compute_behavioral_diff(base, target)
    assert diff["compatibility"] == "breaking"
    assert diff["risk_level"] in {"medium", "high"}
    types = {row["type"] for row in diff["breaking_changes"]}
    assert "input_required_added" in types
    assert "output_required_removed" in types
    assert "protocols_removed" in types
    assert "side_effect_escalated" in types


def test_behavioral_diff_endpoint_and_version_impact_summary() -> None:
    client = TestClient(app)
    base = _manifest("1.0.0")
    create = client.post(
        "/v1/agents",
        json={"namespace": "@versioning", "manifest": base},
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "version-create"},
    )
    assert create.status_code == 200, create.text
    agent_id = create.json()["id"]

    target = _manifest("1.1.0")
    capability = target["capabilities"][0]
    capability["input_schema"]["required"].append("currency")
    capability["side_effect_level"] = "low"
    capability["idempotency_key_required"] = True

    update = client.put(
        f"/v1/agents/{agent_id}",
        json={"manifest": target},
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "version-update"},
    )
    assert update.status_code == 200, update.text

    diff = client.get(
        f"/v1/agents/{agent_id}/versions/1.0.0/behavioral-diff/1.1.0",
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert diff.status_code == 200, diff.text
    payload = diff.json()
    assert payload["diff"]["compatibility"] == "breaking"
    assert any(change["type"] == "input_required_added" for change in payload["diff"]["breaking_changes"])

    versions = client.get(f"/v1/agents/{agent_id}/versions", headers={"X-API-Key": "dev-owner-key"})
    assert versions.status_code == 200
    version_rows = versions.json()["versions"]
    assert version_rows[0]["behavioral_impact_from_previous"] is None
    assert version_rows[1]["behavioral_impact_from_previous"]["compatibility"] == "breaking"
