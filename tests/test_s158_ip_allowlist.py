"""S158 — IP allowlisting tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s158")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s158")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s158")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.ip_allowlist import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_create_allow_rule() -> None:
    _reset()
    r = client.post(
        "/v1/ip-rules",
        json={"agent_id": "a1", "name": "office", "rule_type": "allow", "cidrs": ["10.0.0.0/24"]},
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["rule_type"] == "allow"
    assert body["enabled"] is True


def test_invalid_rule_type() -> None:
    _reset()
    r = client.post(
        "/v1/ip-rules",
        json={"agent_id": "a1", "name": "x", "rule_type": "invalid", "cidrs": ["10.0.0.0/24"]},
        headers=HEADERS,
    )
    assert r.status_code == 400


def test_invalid_cidr() -> None:
    _reset()
    r = client.post(
        "/v1/ip-rules",
        json={"agent_id": "a1", "name": "x", "rule_type": "allow", "cidrs": ["not-a-cidr"]},
        headers=HEADERS,
    )
    assert r.status_code == 400


def test_get_rule() -> None:
    _reset()
    r = client.post(
        "/v1/ip-rules",
        json={"agent_id": "a1", "name": "test", "rule_type": "allow", "cidrs": ["10.0.0.0/8"]},
        headers=HEADERS,
    )
    rid = r.json()["rule_id"]
    r = client.get(f"/v1/ip-rules/{rid}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["rule_id"] == rid


def test_rule_not_found() -> None:
    _reset()
    r = client.get("/v1/ip-rules/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_list_rules() -> None:
    _reset()
    client.post("/v1/ip-rules", json={"agent_id": "a1", "name": "r1", "rule_type": "allow", "cidrs": ["10.0.0.0/8"]}, headers=HEADERS)
    client.post("/v1/ip-rules", json={"agent_id": "a2", "name": "r2", "rule_type": "deny", "cidrs": ["192.168.0.0/16"]}, headers=HEADERS)
    r = client.get("/v1/ip-rules", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_check_allowed() -> None:
    _reset()
    client.post(
        "/v1/ip-rules",
        json={"agent_id": "a1", "name": "office", "rule_type": "allow", "cidrs": ["10.0.0.0/24"]},
        headers=HEADERS,
    )
    r = client.post("/v1/ip-rules/check", json={"agent_id": "a1", "ip_address": "10.0.0.5"}, headers=HEADERS)
    assert r.json()["allowed"] is True


def test_check_not_in_allowlist() -> None:
    _reset()
    client.post(
        "/v1/ip-rules",
        json={"agent_id": "a1", "name": "office", "rule_type": "allow", "cidrs": ["10.0.0.0/24"]},
        headers=HEADERS,
    )
    r = client.post("/v1/ip-rules/check", json={"agent_id": "a1", "ip_address": "192.168.1.1"}, headers=HEADERS)
    assert r.json()["allowed"] is False
    assert r.json()["reason"] == "not_in_allowlist"


def test_deny_takes_precedence() -> None:
    _reset()
    client.post(
        "/v1/ip-rules",
        json={"agent_id": "a1", "name": "allow-all", "rule_type": "allow", "cidrs": ["0.0.0.0/0"]},
        headers=HEADERS,
    )
    client.post(
        "/v1/ip-rules",
        json={"agent_id": "a1", "name": "deny-bad", "rule_type": "deny", "cidrs": ["192.168.1.0/24"]},
        headers=HEADERS,
    )
    r = client.post("/v1/ip-rules/check", json={"agent_id": "a1", "ip_address": "192.168.1.5"}, headers=HEADERS)
    assert r.json()["allowed"] is False
    assert r.json()["reason"] == "denied"


def test_no_rules_allows() -> None:
    _reset()
    r = client.post("/v1/ip-rules/check", json={"agent_id": "a1", "ip_address": "1.2.3.4"}, headers=HEADERS)
    assert r.json()["allowed"] is True
    assert r.json()["reason"] == "no_rules"


def test_disable_rule() -> None:
    _reset()
    r = client.post(
        "/v1/ip-rules",
        json={"agent_id": "a1", "name": "test", "rule_type": "allow", "cidrs": ["10.0.0.0/8"]},
        headers=HEADERS,
    )
    rid = r.json()["rule_id"]
    r = client.post(f"/v1/ip-rules/{rid}/disable", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["enabled"] is False

    # Disabled rule should not be enforced
    r = client.post("/v1/ip-rules/check", json={"agent_id": "a1", "ip_address": "192.168.1.1"}, headers=HEADERS)
    assert r.json()["allowed"] is True


def test_access_log() -> None:
    _reset()
    client.post("/v1/ip-rules/check", json={"agent_id": "a1", "ip_address": "1.2.3.4"}, headers=HEADERS)
    r = client.get("/v1/ip-rules/access-log", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


def test_stats() -> None:
    _reset()
    client.post("/v1/ip-rules", json={"agent_id": "a1", "name": "r1", "rule_type": "allow", "cidrs": ["10.0.0.0/8"]}, headers=HEADERS)
    r = client.get("/v1/ip-rules/stats", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total_rules"] >= 1


if __name__ == "__main__":
    test_create_allow_rule()
    test_invalid_rule_type()
    test_invalid_cidr()
    test_get_rule()
    test_rule_not_found()
    test_list_rules()
    test_check_allowed()
    test_check_not_in_allowlist()
    test_deny_takes_precedence()
    test_no_rules_allows()
    test_disable_rule()
    test_access_log()
    test_stats()
    print("All S158 tests passed!")
