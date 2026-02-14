"""S142 — SCIM 2.0 agent provisioning tests."""
from __future__ import annotations

import json
import os
import tempfile

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key": "owner-dev"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-secret-s142")
os.environ.setdefault("AGENTHUB_AUTH_TOKEN_SECRET", "test-auth-s142")
os.environ.setdefault("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", json.dumps({"test.local": "tok"}))
os.environ.setdefault("AGENTHUB_PROVENANCE_SIGNING_SECRET", "test-prov-s142")
os.environ.setdefault("AGENTHUB_POLICY_SIGNING_SECRET", "test-policy-secret")
os.environ.setdefault("AGENTHUB_VAULT_KEY", "test-vault-key")

from fastapi.testclient import TestClient

from src.api.app import app
from src.identity.storage import reset_for_tests as identity_reset

HEADERS = {"X-API-Key": "test-key"}
_tmpdir = tempfile.mkdtemp()
_db = os.path.join(_tmpdir, "s142.db")

client = TestClient(app)


def _reset() -> None:
    os.environ["AGENTHUB_IDENTITY_DB_PATH"] = _db
    identity_reset(db_path=_db)


def test_service_provider_config() -> None:
    r = client.get("/scim/v2/ServiceProviderConfig")
    assert r.status_code == 200
    body = r.json()
    assert body["patch"]["supported"] is True
    assert body["bulk"]["supported"] is True


def test_schemas() -> None:
    r = client.get("/scim/v2/Schemas")
    assert r.status_code == 200
    assert r.json()["totalResults"] >= 2


def test_resource_types() -> None:
    r = client.get("/scim/v2/ResourceTypes")
    assert r.status_code == 200
    assert r.json()["totalResults"] >= 1


def test_create_user() -> None:
    _reset()
    r = client.post(
        "/scim/v2/Users",
        json={"userName": "scim-agent-1"},
        headers=HEADERS,
    )
    assert r.status_code == 201
    body = r.json()
    assert body["userName"] == "scim-agent-1"
    assert body["active"] is True
    assert "urn:ietf:params:scim:schemas:core:2.0:User" in body["schemas"]


def test_get_user() -> None:
    _reset()
    client.post(
        "/scim/v2/Users",
        json={"userName": "scim-get-1"},
        headers=HEADERS,
    )
    r = client.get("/scim/v2/Users/scim-get-1", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["id"] == "scim-get-1"


def test_get_user_not_found() -> None:
    _reset()
    r = client.get("/scim/v2/Users/nonexistent", headers=HEADERS)
    assert r.status_code == 404


def test_list_users() -> None:
    _reset()
    client.post("/scim/v2/Users", json={"userName": "scim-list-1"}, headers=HEADERS)
    client.post("/scim/v2/Users", json={"userName": "scim-list-2"}, headers=HEADERS)
    r = client.get("/scim/v2/Users", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["totalResults"] >= 2


def test_list_with_filter() -> None:
    _reset()
    client.post("/scim/v2/Users", json={"userName": "scim-filter-1"}, headers=HEADERS)
    client.post("/scim/v2/Users", json={"userName": "scim-filter-2"}, headers=HEADERS)
    r = client.get(
        '/scim/v2/Users?filter=userName eq "scim-filter-1"',
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["totalResults"] == 1
    assert body["Resources"][0]["userName"] == "scim-filter-1"


def test_replace_user() -> None:
    _reset()
    client.post("/scim/v2/Users", json={"userName": "scim-put"}, headers=HEADERS)
    r = client.put(
        "/scim/v2/Users/scim-put",
        json={"active": False},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["active"] is False


def test_patch_user() -> None:
    _reset()
    client.post("/scim/v2/Users", json={"userName": "scim-patch"}, headers=HEADERS)
    r = client.patch(
        "/scim/v2/Users/scim-patch",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["active"] is False


def test_delete_user() -> None:
    _reset()
    client.post("/scim/v2/Users", json={"userName": "scim-del"}, headers=HEADERS)
    r = client.delete("/scim/v2/Users/scim-del", headers=HEADERS)
    assert r.status_code == 204


def test_bulk_operations() -> None:
    _reset()
    r = client.post(
        "/scim/v2/Bulk",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": [
                {"method": "POST", "path": "/Users", "bulkId": "b1", "data": {"userName": "bulk-1"}},
                {"method": "POST", "path": "/Users", "bulkId": "b2", "data": {"userName": "bulk-2"}},
            ],
        },
        headers=HEADERS,
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body["Operations"]) == 2
    assert body["Operations"][0]["status"] == "201"
    assert body["Operations"][1]["status"] == "201"


def test_create_with_extension() -> None:
    _reset()
    r = client.post(
        "/scim/v2/Users",
        json={
            "userName": "scim-ext",
            "urn:ietf:params:scim:schemas:extension:agenthub:2.0:Agent": {
                "credentialType": "api_key",
                "humanPrincipalId": "admin@corp.com",
            },
        },
        headers=HEADERS,
    )
    assert r.status_code == 201
    ext = r.json().get("urn:ietf:params:scim:schemas:extension:agenthub:2.0:Agent", {})
    assert ext["humanPrincipalId"] == "admin@corp.com"


if __name__ == "__main__":
    test_service_provider_config()
    test_schemas()
    test_resource_types()
    test_create_user()
    test_get_user()
    test_get_user_not_found()
    test_list_users()
    test_list_with_filter()
    test_replace_user()
    test_patch_user()
    test_delete_user()
    test_bulk_operations()
    test_create_with_extension()
    print("All S142 tests passed!")
