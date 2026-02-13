from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.store import DEFAULT_DB_PATH, STORE
from src.devhub import service as devhub_service
from src.discovery.service import DISCOVERY_SERVICE

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "specs" / "manifest" / "examples" / "simple-tool-agent.yaml"


@pytest.fixture(autouse=True)
def isolate_devhub_and_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original_registry_db = os.getenv("AGENTHUB_REGISTRY_DB_PATH")
    original_devhub_db = os.getenv("AGENTHUB_DEVHUB_DB_PATH")
    registry_db = tmp_path / "registry.db"
    devhub_db = tmp_path / "devhub.db"
    monkeypatch.setenv("AGENTHUB_REGISTRY_DB_PATH", str(registry_db))
    monkeypatch.setenv("AGENTHUB_DEVHUB_DB_PATH", str(devhub_db))
    monkeypatch.setenv("AGENTHUB_EVAL_RESULTS_PATH", str(tmp_path / "evals.json"))
    STORE.reset_for_tests(db_path=registry_db)
    devhub_service.reset_for_tests(db_path=devhub_db)
    yield
    STORE.reconfigure(db_path=Path(original_registry_db) if original_registry_db else DEFAULT_DB_PATH)
    devhub_service.reconfigure(db_path=Path(original_devhub_db) if original_devhub_db else devhub_db)
    DISCOVERY_SERVICE.refresh_index(force=True)


def _manifest(version: str) -> dict:
    loaded = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
    loaded["identity"]["version"] = version
    return loaded


def _register_and_update(client: TestClient) -> str:
    created = client.post(
        "/v1/agents",
        json={"namespace": "@devhub", "manifest": _manifest("1.0.0")},
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s43-create-1"},
    )
    assert created.status_code == 200, created.text
    agent_id = created.json()["id"]

    updated = client.put(
        f"/v1/agents/{agent_id}",
        json={"manifest": _manifest("1.1.0")},
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s43-update-1"},
    )
    assert updated.status_code == 200, updated.text
    return agent_id


def test_devhub_collaboration_review_gate_and_promotion_flow() -> None:
    client = TestClient(app)
    agent_id = _register_and_update(client)

    created_review = client.post(
        "/v1/devhub/reviews",
        json={"agent_id": agent_id, "version": "1.1.0", "approvals_required": 2},
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s43-review-create-1"},
    )
    assert created_review.status_code == 200, created_review.text
    review = created_review.json()
    review_id = review["review_id"]
    assert review["status"] == "pending"

    list_reviews = client.get("/v1/devhub/reviews", headers={"X-API-Key": "dev-owner-key"})
    assert list_reviews.status_code == 200
    assert len(list_reviews.json()["data"]) == 1

    blocked_decision = client.post(
        f"/v1/devhub/reviews/{review_id}/decision",
        json={"decision": "approve", "note": "viewer should be blocked"},
        headers={
            "X-API-Key": "partner-owner-key",
            "X-Operator-Role": "viewer",
            "Idempotency-Key": "s43-review-decision-blocked-1",
        },
    )
    assert blocked_decision.status_code == 403

    approve_one = client.post(
        f"/v1/devhub/reviews/{review_id}/decision",
        json={"decision": "approve", "note": "first approval"},
        headers={
            "X-API-Key": "dev-owner-key",
            "X-Operator-Role": "admin",
            "Idempotency-Key": "s43-review-approve-1",
        },
    )
    assert approve_one.status_code == 200
    assert approve_one.json()["status"] == "pending"

    approve_two = client.post(
        f"/v1/devhub/reviews/{review_id}/decision",
        json={"decision": "approve", "note": "second approval"},
        headers={
            "X-API-Key": "platform-owner-key",
            "X-Operator-Role": "admin",
            "Idempotency-Key": "s43-review-approve-2",
        },
    )
    assert approve_two.status_code == 200
    assert approve_two.json()["status"] == "approved"

    promotion = client.post(
        f"/v1/devhub/reviews/{review_id}/promote",
        headers={
            "X-API-Key": "dev-owner-key",
            "X-Operator-Role": "admin",
            "Idempotency-Key": "s43-review-promote-1",
        },
    )
    assert promotion.status_code == 200
    assert promotion.json()["status"] == "promoted"

    promotions = client.get("/v1/devhub/promotions", headers={"X-API-Key": "dev-owner-key"})
    assert promotions.status_code == 200
    assert len(promotions.json()["data"]) == 1


def test_devhub_review_rejection_blocks_promotion_and_duplicate_votes() -> None:
    client = TestClient(app)
    agent_id = _register_and_update(client)

    review = client.post(
        "/v1/devhub/reviews",
        json={"agent_id": agent_id, "version": "1.1.0", "approvals_required": 2},
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s43-review-create-2"},
    )
    assert review.status_code == 200
    review_id = review.json()["review_id"]

    reject = client.post(
        f"/v1/devhub/reviews/{review_id}/decision",
        json={"decision": "reject", "note": "security signoff missing"},
        headers={
            "X-API-Key": "platform-owner-key",
            "X-Operator-Role": "admin",
            "Idempotency-Key": "s43-review-reject-1",
        },
    )
    assert reject.status_code == 200
    assert reject.json()["status"] == "rejected"

    duplicate_reject = client.post(
        f"/v1/devhub/reviews/{review_id}/decision",
        json={"decision": "reject", "note": "duplicate decision"},
        headers={
            "X-API-Key": "platform-owner-key",
            "X-Operator-Role": "admin",
            "Idempotency-Key": "s43-review-reject-2",
        },
    )
    assert duplicate_reject.status_code == 400

    promote = client.post(
        f"/v1/devhub/reviews/{review_id}/promote",
        headers={
            "X-API-Key": "dev-owner-key",
            "X-Operator-Role": "admin",
            "Idempotency-Key": "s43-review-promote-2",
        },
    )
    assert promote.status_code == 400
