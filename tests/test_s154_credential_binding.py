"""S154 — Credential binding rules tests."""
from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s154")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s154")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s154")
os.environ.setdefault("AGENTHUB_POLICY_SIGNING_SECRET", "test-policy-secret")

from fastapi.testclient import TestClient

from src.api.app import app
from src.runtime.credential_binding import reset_for_tests

HEADERS = {"X-API-Key": "test-key"}
client = TestClient(app)


def _reset() -> None:
    reset_for_tests()


def test_create_binding() -> None:
    _reset()
    r = client.post(
        "/v1/credential-bindings",
        json={
            "credential_id": "cred1",
            "agent_id": "a1",
            "binding_type": "ip",
            "constraints": {"allowed_ips": ["10.0.0.1", "10.0.0.2"]},
        },
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["binding_type"] == "ip"
    assert body["active"] is True


def test_invalid_binding_type() -> None:
    _reset()
    r = client.post(
        "/v1/credential-bindings",
        json={"credential_id": "c1", "agent_id": "a1", "binding_type": "invalid", "constraints": {"x": 1}},
        headers=HEADERS,
    )
    assert r.status_code == 400


def test_get_binding() -> None:
    _reset()
    r = client.post(
        "/v1/credential-bindings",
        json={"credential_id": "c1", "agent_id": "a1", "binding_type": "ip", "constraints": {"allowed_ips": ["10.0.0.1"]}},
        headers=HEADERS,
    )
    bid = r.json()["binding_id"]
    r = client.get(f"/v1/credential-bindings/{bid}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["binding_id"] == bid


def test_binding_not_found() -> None:
    _reset()
    r = client.get("/v1/credential-bindings/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_list_bindings() -> None:
    _reset()
    client.post(
        "/v1/credential-bindings",
        json={"credential_id": "c1", "agent_id": "a1", "binding_type": "ip", "constraints": {"allowed_ips": ["10.0.0.1"]}},
        headers=HEADERS,
    )
    client.post(
        "/v1/credential-bindings",
        json={"credential_id": "c2", "agent_id": "a2", "binding_type": "environment", "constraints": {"environment": "prod"}},
        headers=HEADERS,
    )
    r = client.get("/v1/credential-bindings", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 2


def test_validate_ip_allowed() -> None:
    _reset()
    client.post(
        "/v1/credential-bindings",
        json={"credential_id": "c1", "agent_id": "a1", "binding_type": "ip", "constraints": {"allowed_ips": ["10.0.0.1"]}},
        headers=HEADERS,
    )

    r = client.post(
        "/v1/credential-bindings/validate",
        json={"credential_id": "c1", "agent_id": "a1", "context": {"ip": "10.0.0.1"}},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["valid"] is True


def test_validate_ip_denied() -> None:
    _reset()
    client.post(
        "/v1/credential-bindings",
        json={"credential_id": "c1", "agent_id": "a1", "binding_type": "ip", "constraints": {"allowed_ips": ["10.0.0.1"]}},
        headers=HEADERS,
    )

    r = client.post(
        "/v1/credential-bindings/validate",
        json={"credential_id": "c1", "agent_id": "a1", "context": {"ip": "192.168.1.1"}},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["valid"] is False
    assert len(r.json()["violations"]) >= 1


def test_validate_environment() -> None:
    _reset()
    client.post(
        "/v1/credential-bindings",
        json={"credential_id": "c1", "agent_id": "a1", "binding_type": "environment", "constraints": {"environment": "production"}},
        headers=HEADERS,
    )

    r = client.post(
        "/v1/credential-bindings/validate",
        json={"credential_id": "c1", "agent_id": "a1", "context": {"environment": "staging"}},
        headers=HEADERS,
    )
    assert r.json()["valid"] is False


def test_validate_no_bindings() -> None:
    _reset()
    r = client.post(
        "/v1/credential-bindings/validate",
        json={"credential_id": "c1", "agent_id": "a1", "context": {"ip": "1.2.3.4"}},
        headers=HEADERS,
    )
    assert r.json()["valid"] is True
    assert r.json()["reason"] == "no_bindings"


def test_deactivate_binding() -> None:
    _reset()
    r = client.post(
        "/v1/credential-bindings",
        json={"credential_id": "c1", "agent_id": "a1", "binding_type": "ip", "constraints": {"allowed_ips": ["10.0.0.1"]}},
        headers=HEADERS,
    )
    bid = r.json()["binding_id"]

    r = client.post(f"/v1/credential-bindings/{bid}/deactivate", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["active"] is False

    # Deactivated binding should not be enforced
    r = client.post(
        "/v1/credential-bindings/validate",
        json={"credential_id": "c1", "agent_id": "a1", "context": {"ip": "192.168.1.1"}},
        headers=HEADERS,
    )
    assert r.json()["valid"] is True


def test_validation_log() -> None:
    _reset()
    client.post(
        "/v1/credential-bindings",
        json={"credential_id": "c1", "agent_id": "a1", "binding_type": "ip", "constraints": {"allowed_ips": ["10.0.0.1"]}},
        headers=HEADERS,
    )
    client.post(
        "/v1/credential-bindings/validate",
        json={"credential_id": "c1", "agent_id": "a1", "context": {"ip": "10.0.0.1"}},
        headers=HEADERS,
    )

    r = client.get("/v1/credential-bindings/validations", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


def test_stats() -> None:
    _reset()
    client.post(
        "/v1/credential-bindings",
        json={"credential_id": "c1", "agent_id": "a1", "binding_type": "ip", "constraints": {"allowed_ips": ["10.0.0.1"]}},
        headers=HEADERS,
    )
    r = client.get("/v1/credential-bindings/stats", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["total_bindings"] >= 1
    assert body["active_bindings"] >= 1


if __name__ == "__main__":
    test_create_binding()
    test_invalid_binding_type()
    test_get_binding()
    test_binding_not_found()
    test_list_bindings()
    test_validate_ip_allowed()
    test_validate_ip_denied()
    test_validate_environment()
    test_validate_no_bindings()
    test_deactivate_binding()
    test_validation_log()
    test_stats()
    print("All S154 tests passed!")
