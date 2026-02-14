"""S144 — Agent access review / certification campaign tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s144")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s144")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s144")
os.environ.setdefault("AGENTHUB_POLICY_SIGNING_SECRET", "test-policy-secret")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.access_review import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_create_campaign() -> None:
    _reset()
    r = client.post(
        "/v1/access-review/campaigns",
        json={"name": "Q1 2026 Review", "campaign_type": "quarterly"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "Q1 2026 Review"
    assert body["campaign_type"] == "quarterly"
    assert body["status"] == "active"


def test_create_campaign_with_agents() -> None:
    _reset()
    r = client.post(
        "/v1/access-review/campaigns",
        json={"name": "Agent review", "agent_ids": ["a1", "a2", "a3"]},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["total_items"] == 3
    assert body["pending_count"] == 3


def test_list_campaigns() -> None:
    _reset()
    client.post("/v1/access-review/campaigns", json={"name": "C1"}, headers=HEADERS)
    client.post("/v1/access-review/campaigns", json={"name": "C2"}, headers=HEADERS)
    r = client.get("/v1/access-review/campaigns", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_get_campaign() -> None:
    _reset()
    r = client.post("/v1/access-review/campaigns", json={"name": "C1"}, headers=HEADERS)
    cid = r.json()["campaign_id"]
    r = client.get(f"/v1/access-review/campaigns/{cid}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["campaign_id"] == cid


def test_campaign_not_found() -> None:
    _reset()
    r = client.get("/v1/access-review/campaigns/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_add_review_item() -> None:
    _reset()
    r = client.post("/v1/access-review/campaigns", json={"name": "C1"}, headers=HEADERS)
    cid = r.json()["campaign_id"]

    r = client.post(
        f"/v1/access-review/campaigns/{cid}/items",
        json={"agent_id": "a1", "entitlement_type": "api_access"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["agent_id"] == "a1"
    assert r.json()["decision"] == "pending"


def test_list_review_items() -> None:
    _reset()
    r = client.post(
        "/v1/access-review/campaigns",
        json={"name": "C1", "agent_ids": ["a1", "a2"]},
        headers=HEADERS,
    )
    cid = r.json()["campaign_id"]

    r = client.get(f"/v1/access-review/campaigns/{cid}/items", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] == 2


def test_certify_item() -> None:
    _reset()
    r = client.post(
        "/v1/access-review/campaigns",
        json={"name": "C1", "agent_ids": ["a1"]},
        headers=HEADERS,
    )
    cid = r.json()["campaign_id"]

    r = client.get(f"/v1/access-review/campaigns/{cid}/items", headers=HEADERS)
    item_id = r.json()["items"][0]["item_id"]

    r = client.post(
        f"/v1/access-review/items/{item_id}/decide",
        json={"decision": "certified", "reason": "still needed"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "certified"


def test_revoke_item() -> None:
    _reset()
    r = client.post(
        "/v1/access-review/campaigns",
        json={"name": "C1", "agent_ids": ["a1"]},
        headers=HEADERS,
    )
    cid = r.json()["campaign_id"]

    r = client.get(f"/v1/access-review/campaigns/{cid}/items", headers=HEADERS)
    item_id = r.json()["items"][0]["item_id"]

    r = client.post(
        f"/v1/access-review/items/{item_id}/decide",
        json={"decision": "revoked", "reason": "no longer needed"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "revoked"


def test_cannot_decide_twice() -> None:
    _reset()
    r = client.post(
        "/v1/access-review/campaigns",
        json={"name": "C1", "agent_ids": ["a1"]},
        headers=HEADERS,
    )
    cid = r.json()["campaign_id"]

    r = client.get(f"/v1/access-review/campaigns/{cid}/items", headers=HEADERS)
    item_id = r.json()["items"][0]["item_id"]

    client.post(
        f"/v1/access-review/items/{item_id}/decide",
        json={"decision": "certified"},
        headers=HEADERS,
    )
    r = client.post(
        f"/v1/access-review/items/{item_id}/decide",
        json={"decision": "revoked"},
        headers=HEADERS,
    )
    assert r.status_code == 400


def test_campaign_auto_completes() -> None:
    _reset()
    r = client.post(
        "/v1/access-review/campaigns",
        json={"name": "C1", "agent_ids": ["a1"]},
        headers=HEADERS,
    )
    cid = r.json()["campaign_id"]

    r = client.get(f"/v1/access-review/campaigns/{cid}/items", headers=HEADERS)
    item_id = r.json()["items"][0]["item_id"]

    client.post(
        f"/v1/access-review/items/{item_id}/decide",
        json={"decision": "certified"},
        headers=HEADERS,
    )

    r = client.get(f"/v1/access-review/campaigns/{cid}", headers=HEADERS)
    assert r.json()["status"] == "completed"


def test_campaign_progress() -> None:
    _reset()
    r = client.post(
        "/v1/access-review/campaigns",
        json={"name": "C1", "agent_ids": ["a1", "a2"]},
        headers=HEADERS,
    )
    cid = r.json()["campaign_id"]

    r = client.get(f"/v1/access-review/campaigns/{cid}/progress", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["total_items"] == 2
    assert body["pending"] == 2
    assert body["completion_rate"] == 0.0


def test_compliance_summary() -> None:
    _reset()
    client.post(
        "/v1/access-review/campaigns",
        json={"name": "C1", "agent_ids": ["a1"]},
        headers=HEADERS,
    )

    r = client.get("/v1/access-review/compliance", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["total_campaigns"] >= 1
    assert body["items_pending"] >= 1


def test_invalid_campaign_type() -> None:
    _reset()
    r = client.post(
        "/v1/access-review/campaigns",
        json={"name": "C1", "campaign_type": "invalid_type"},
        headers=HEADERS,
    )
    assert r.status_code == 400


if __name__ == "__main__":
    test_create_campaign()
    test_create_campaign_with_agents()
    test_list_campaigns()
    test_get_campaign()
    test_campaign_not_found()
    test_add_review_item()
    test_list_review_items()
    test_certify_item()
    test_revoke_item()
    test_cannot_decide_twice()
    test_campaign_auto_completes()
    test_campaign_progress()
    test_compliance_summary()
    test_invalid_campaign_type()
    print("All S144 tests passed!")
