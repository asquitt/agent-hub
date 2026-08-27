from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.common.sqlite_collections import write_collection
from src.identity.jwt_tokens import issue_jwt, verify_jwt
from src.identity.oauth_clients import OAUTH_CLIENT_STORE, OAuthClientStore
from src.runtime.audit_streaming import (
    EVENT_OAUTH_CLIENT_AUTHORITY_BOUND,
    query_events,
    reset_for_tests as reset_audit_for_tests,
)


@pytest.fixture(autouse=True)
def isolate_oauth_clients(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    identity_db = tmp_path / "identity.db"
    monkeypatch.setenv("AGENTHUB_IDENTITY_DB_PATH", str(identity_db))
    monkeypatch.setenv("AGENTHUB_IDENTITY_SIGNING_SECRET", "oauth-containment-test-signing-secret-32-bytes")
    monkeypatch.setenv(
        "AGENTHUB_API_KEYS_JSON",
        json.dumps(
            {
                "dev-owner-key": "owner-dev",
                "limited-oauth-key": {
                    "owner": "owner-limited",
                    "scopes": ["oauth.register", "read"],
                    "roles": ["member"],
                },
                "read-only-key": {
                    "owner": "owner-read-only",
                    "scopes": ["read"],
                    "roles": ["member"],
                },
            }
        ),
    )
    monkeypatch.setenv(
        "AGENTHUB_OWNER_TENANTS_JSON",
        json.dumps(
            {
                "owner-dev": ["tenant-default"],
                "owner-limited": ["tenant-a"],
                "owner-read-only": ["tenant-a"],
            }
        ),
    )
    OAUTH_CLIENT_STORE.reset_for_tests(db_path=identity_db)
    reset_audit_for_tests()
    return identity_db


def _register(client: TestClient, *, scope: str = "read runtime.execute") -> dict[str, object]:
    response = client.post(
        "/v1/oauth/register",
        json={"client_name": "contained-client", "grant_types": ["client_credentials"], "scope": scope},
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _token(client: TestClient, registration: dict[str, object], *, scope: str | None = None):
    form = {
        "grant_type": "client_credentials",
        "client_id": str(registration["client_id"]),
        "client_secret": str(registration["client_secret"]),
    }
    if scope is not None:
        form["scope"] = scope
    return client.post("/v1/oauth/token", data=form)


def test_token_issues_only_requested_registered_scope() -> None:
    with TestClient(app) as client:
        registration = _register(client)
        response = _token(client, registration, scope="read")

    assert response.status_code == 200, response.text
    assert response.json()["scope"] == "read"
    claims = verify_jwt(response.json()["access_token"], issuer="urn:agenthub:registry")
    assert claims["scopes"] == ["read"]


def test_token_rejects_scope_expansion_without_issuing_token() -> None:
    with TestClient(app) as client:
        registration = _register(client, scope="read")
        response = _token(client, registration, scope="read runtime.execute")

    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_scope"
    assert "access_token" not in response.json()


def test_registration_rejects_scope_outside_registrar_authority() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/v1/oauth/register",
            json={"client_name": "scope-amplifier", "grant_types": ["client_credentials"], "scope": "*"},
            headers={"X-API-Key": "limited-oauth-key", "X-Tenant-ID": "tenant-a"},
        )

    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "invalid_scope"


def test_client_and_token_preserve_registrar_authority() -> None:
    with TestClient(app) as client:
        registration_response = client.post(
            "/v1/oauth/register",
            json={"client_name": "tenant-client", "grant_types": ["client_credentials"], "scope": "read"},
            headers={"X-API-Key": "limited-oauth-key", "X-Tenant-ID": "tenant-a"},
        )
        assert registration_response.status_code == 200, registration_response.text
        registration = registration_response.json()
        token_response = _token(client, registration, scope="read")

    assert registration["owner"] == "owner-limited"
    assert registration["tenant_id"] == "tenant-a"
    persisted = OAUTH_CLIENT_STORE.get_client(str(registration["client_id"]))
    assert persisted is not None
    assert persisted["owner"] == "owner-limited"
    assert persisted["tenant_id"] == "tenant-a"
    assert token_response.status_code == 200, token_response.text
    claims = verify_jwt(token_response.json()["access_token"], issuer="urn:agenthub:registry")
    assert claims["sub"] == "owner-limited"
    assert claims["agent_id"] == registration["client_id"]
    assert claims["tenant_id"] == "tenant-a"
    assert claims["principal_type"] == "oauth_client"
    assert claims["token_use"] == "oauth_client"


def test_token_rejects_unimplemented_grant() -> None:
    with TestClient(app) as client:
        registration = _register(client)
        response = client.post(
            "/v1/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": str(registration["client_id"]),
                "client_secret": str(registration["client_secret"]),
            },
        )

    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "unsupported_grant_type"


def test_token_without_scope_uses_registered_scope() -> None:
    with TestClient(app) as client:
        registration = _register(client, scope="runtime.execute read read")
        response = _token(client, registration)

    assert response.status_code == 200, response.text
    assert response.json()["scope"] == "read runtime.execute"
    claims = verify_jwt(response.json()["access_token"], issuer="urn:agenthub:registry")
    assert claims["scopes"] == ["read", "runtime.execute"]


@pytest.mark.parametrize("grant_types", [["authorization_code"], ["refresh_token"], ["client_credentials", "refresh_token"]])
def test_registration_rejects_invalid_or_unimplemented_grants(grant_types: list[str]) -> None:
    with TestClient(app) as client:
        response = client.post(
            "/v1/oauth/register",
            json={"client_name": "invalid-grant-client", "grant_types": grant_types, "scope": "read"},
            headers={"X-API-Key": "dev-owner-key"},
        )

    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_client_metadata"


def test_registration_rejects_empty_grant_list() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/v1/oauth/register",
            json={"client_name": "empty-grant-client", "grant_types": [], "scope": "read"},
            headers={"X-API-Key": "dev-owner-key"},
        )

    assert response.status_code == 422


def test_client_record_persists_across_process_restart(isolate_oauth_clients: Path) -> None:
    first_store = OAuthClientStore(db_path=isolate_oauth_clients)
    registration = first_store.register_client(
        client_name="persistent-client",
        grant_types=["client_credentials"],
        scope="read",
        owner="owner-persistent",
        tenant_id="tenant-persistent",
        authorized_scopes=["read"],
    )

    with sqlite3.connect(isolate_oauth_clients) as connection:
        row = connection.execute(
            "SELECT payload_json FROM collection_store WHERE scope = ? AND collection_name = ?",
            ("identity", "oauth_clients"),
        ).fetchone()
    assert row is not None
    persisted_payload = str(row[0])
    assert str(registration["client_secret"]) not in persisted_payload
    assert hashlib.sha256(str(registration["client_secret"]).encode("utf-8")).hexdigest() in persisted_payload

    env = os.environ.copy()
    env.update(
        {
            "OAUTH_TEST_DB": str(isolate_oauth_clients),
            "OAUTH_TEST_CLIENT_ID": str(registration["client_id"]),
            "OAUTH_TEST_CLIENT_SECRET": str(registration["client_secret"]),
        }
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json, os; "
                "from src.identity.oauth_clients import OAuthClientStore; "
                "store = OAuthClientStore(os.environ['OAUTH_TEST_DB']); "
                "result = store.authenticate_client(os.environ['OAUTH_TEST_CLIENT_ID'], "
                "os.environ['OAUTH_TEST_CLIENT_SECRET']); "
                "print(json.dumps(result, sort_keys=True))"
            ),
        ],
        check=False,
        capture_output=True,
        env=env,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    authenticated = json.loads(completed.stdout)

    assert authenticated is not None
    assert authenticated["scope"] == "read"
    assert authenticated["owner"] == "owner-persistent"
    assert authenticated["tenant_id"] == "tenant-persistent"
    assert "client_secret" not in authenticated
    assert "client_secret_hash" not in authenticated
    assert OAuthClientStore(db_path=isolate_oauth_clients).authenticate_client(
        str(registration["client_id"]), "wrong-secret"
    ) is None


def test_malformed_persisted_client_fails_closed(isolate_oauth_clients: Path) -> None:
    secret = "known-test-secret"
    write_collection(
        db_path=isolate_oauth_clients,
        scope="identity",
        collection_name="oauth_clients",
        rows=[
            {
                "client_id": "client_malformed",
                "client_secret_hash": hashlib.sha256(secret.encode("utf-8")).hexdigest(),
                "client_name": "malformed-client",
                "grant_types": ["authorization_code"],
                "scope": "read",
                "redirect_uris": [],
                "created_at": 1,
            }
        ],
    )

    store = OAuthClientStore(db_path=isolate_oauth_clients)
    assert store.authenticate_client("client_malformed", secret) is None
    assert store.get_client("client_malformed") is None


def test_base_client_can_bind_authority_and_mint_replacement_token(isolate_oauth_clients: Path) -> None:
    secret = "legacy-client-secret"
    write_collection(
        db_path=isolate_oauth_clients,
        scope="identity",
        collection_name="oauth_clients",
        rows=[
            {
                "client_id": "client_legacy",
                "client_secret_hash": hashlib.sha256(secret.encode("utf-8")).hexdigest(),
                "client_name": "legacy-client",
                "grant_types": ["client_credentials"],
                "scope": "read",
                "redirect_uris": [],
                "created_at": 1,
            }
        ],
    )
    old_tenantless_token = issue_jwt(
        subject="client_legacy",
        agent_id="client_legacy",
        scopes=["read"],
        issuer="urn:agenthub:registry",
    )["token"]

    with TestClient(app) as client:
        before = client.post(
            "/v1/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "client_legacy",
                "client_secret": secret,
            },
        )
        unauthenticated = client.post(
            "/v1/oauth/clients/client_legacy/authority/register",
            json={"client_secret": secret},
            headers={"X-Tenant-ID": "tenant-a", "Idempotency-Key": "reject-unauthenticated-binding"},
        )
        under_scoped = client.post(
            "/v1/oauth/clients/client_legacy/authority/register",
            json={"client_secret": secret},
            headers={
                "X-API-Key": "read-only-key",
                "X-Tenant-ID": "tenant-a",
                "Idempotency-Key": "reject-under-scoped-binding",
            },
        )
        wrong_secret = client.post(
            "/v1/oauth/clients/client_legacy/authority/register",
            json={"client_secret": "wrong-secret"},
            headers={
                "X-API-Key": "limited-oauth-key",
                "X-Tenant-ID": "tenant-a",
                "Idempotency-Key": "reject-wrong-legacy-secret",
            },
        )
        assert query_events(event_type=EVENT_OAUTH_CLIENT_AUTHORITY_BOUND) == []

        bound = client.post(
            "/v1/oauth/clients/client_legacy/authority/register",
            json={"client_secret": secret},
            headers={
                "X-API-Key": "limited-oauth-key",
                "X-Tenant-ID": "tenant-a",
                "Idempotency-Key": "bind-client-legacy-authority",
            },
        )
        replay = client.post(
            "/v1/oauth/clients/client_legacy/authority/register",
            json={"client_secret": secret},
            headers={
                "X-API-Key": "limited-oauth-key",
                "X-Tenant-ID": "tenant-a",
                "Idempotency-Key": "reject-client-authority-replay",
            },
        )
        cross_owner = client.post(
            "/v1/oauth/clients/client_legacy/authority/register",
            json={"client_secret": secret},
            headers={
                "X-API-Key": "dev-owner-key",
                "X-Tenant-ID": "tenant-default",
                "Idempotency-Key": "reject-cross-owner-authority-rebind",
            },
        )
        after = client.post(
            "/v1/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "client_legacy",
                "client_secret": secret,
            },
        )
        old_verification = client.post(
            "/v1/identity/tokens/jwt/verify",
            json={"token": old_tenantless_token},
            headers={"X-API-Key": "dev-owner-key", "X-Tenant-ID": "tenant-default"},
        )

    assert before.status_code == 401
    assert unauthenticated.status_code == 401
    assert under_scoped.status_code == 403
    assert wrong_secret.status_code == 401
    assert bound.status_code == 200, bound.text
    assert bound.json()["owner"] == "owner-limited"
    assert bound.json()["tenant_id"] == "tenant-a"
    assert replay.status_code == 401
    assert cross_owner.status_code == 401
    assert after.status_code == 200, after.text
    assert old_verification.status_code == 200, old_verification.text
    assert old_verification.json()["valid"] is False
    claims = verify_jwt(after.json()["access_token"], issuer="urn:agenthub:registry")
    assert claims["sub"] == "owner-limited"
    assert claims["tenant_id"] == "tenant-a"
    assert claims["token_use"] == "oauth_client"

    durable_binding = OAuthClientStore(db_path=isolate_oauth_clients).get_authority_binding("client_legacy")
    assert durable_binding is not None
    assert durable_binding["event_id"] == bound.json()["authority_binding_id"]
    assert durable_binding["event_type"] == EVENT_OAUTH_CLIENT_AUTHORITY_BOUND
    assert durable_binding["client_id"] == "client_legacy"
    assert durable_binding["actor"] == "owner-limited"
    assert durable_binding["tenant_id"] == "tenant-a"

    events = query_events(event_type=EVENT_OAUTH_CLIENT_AUTHORITY_BOUND)
    assert len(events) == 1
    assert events[0]["actor"] == "owner-limited"
    assert events[0]["resource"] == "client_legacy"
    assert events[0]["detail"]["authority_binding_id"] == durable_binding["event_id"]

    env = os.environ.copy()
    env.update(
        {
            "OAUTH_TEST_DB": str(isolate_oauth_clients),
            "OAUTH_TEST_CLIENT_ID": "client_legacy",
            "OAUTH_TEST_CLIENT_SECRET": secret,
        }
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json, os; "
                "from src.identity.oauth_clients import OAuthClientStore; "
                "store = OAuthClientStore(os.environ['OAUTH_TEST_DB']); "
                "print(json.dumps({'client': store.authenticate_client("
                "os.environ['OAUTH_TEST_CLIENT_ID'], os.environ['OAUTH_TEST_CLIENT_SECRET']), "
                "'audit': store.get_authority_binding(os.environ['OAUTH_TEST_CLIENT_ID'])}, sort_keys=True))"
            ),
        ],
        check=False,
        capture_output=True,
        env=env,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    restarted = json.loads(completed.stdout)
    assert restarted["client"]["owner"] == "owner-limited"
    assert restarted["client"]["tenant_id"] == "tenant-a"
    assert restarted["audit"] == durable_binding


def test_legacy_authority_binding_is_atomic_across_processes(isolate_oauth_clients: Path) -> None:
    secret = "concurrent-legacy-client-secret"
    write_collection(
        db_path=isolate_oauth_clients,
        scope="identity",
        collection_name="oauth_clients",
        rows=[
            {
                "client_id": "client_concurrent_legacy",
                "client_secret_hash": hashlib.sha256(secret.encode("utf-8")).hexdigest(),
                "client_name": "concurrent-legacy-client",
                "grant_types": ["client_credentials"],
                "scope": "read",
                "redirect_uris": [],
                "created_at": 1,
            }
        ],
    )
    worker_code = """
import json
import os
import sys
from src.identity.oauth_clients import OAuthClientStore

store = OAuthClientStore(os.environ["OAUTH_TEST_DB"])
print("ready", flush=True)
sys.stdin.read(1)
result = store.bind_legacy_client_authority(
    client_id="client_concurrent_legacy",
    client_secret=os.environ["OAUTH_TEST_CLIENT_SECRET"],
    owner=os.environ["OAUTH_TEST_OWNER"],
    tenant_id=os.environ["OAUTH_TEST_TENANT"],
    authorized_scopes=["read"],
)
print(json.dumps(result, sort_keys=True), flush=True)
"""
    workers: list[subprocess.Popen[str]] = []
    for index in range(4):
        env = os.environ.copy()
        env.update(
            {
                "OAUTH_TEST_DB": str(isolate_oauth_clients),
                "OAUTH_TEST_CLIENT_SECRET": secret,
                "OAUTH_TEST_OWNER": f"owner-{index}",
                "OAUTH_TEST_TENANT": f"tenant-{index}",
            }
        )
        worker = subprocess.Popen(
            [sys.executable, "-c", worker_code],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
        )
        assert worker.stdout is not None
        assert worker.stdout.readline().strip() == "ready"
        workers.append(worker)

    for worker in workers:
        assert worker.stdin is not None
        worker.stdin.write("x")
        worker.stdin.flush()

    results: list[dict[str, object] | None] = []
    for worker in workers:
        stdout, stderr = worker.communicate(timeout=10)
        assert worker.returncode == 0, stderr
        results.append(json.loads(stdout))

    winners = [result for result in results if result is not None]
    assert len(winners) == 1
    winner = winners[0]
    store = OAuthClientStore(db_path=isolate_oauth_clients)
    persisted = store.authenticate_client("client_concurrent_legacy", secret)
    assert persisted is not None
    assert persisted["owner"] == winner["owner"]
    assert persisted["tenant_id"] == winner["tenant_id"]
    binding = store.get_authority_binding("client_concurrent_legacy")
    assert binding is not None
    assert binding["event_id"] == winner["authority_binding_id"]

    env = os.environ.copy()
    env.update(
        {
            "OAUTH_TEST_DB": str(isolate_oauth_clients),
            "OAUTH_TEST_CLIENT_ID": "client_concurrent_legacy",
            "OAUTH_TEST_CLIENT_SECRET": secret,
        }
    )
    restarted = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json, os; "
                "from src.identity.oauth_clients import OAuthClientStore; "
                "store = OAuthClientStore(os.environ['OAUTH_TEST_DB']); "
                "print(json.dumps({'client': store.authenticate_client("
                "os.environ['OAUTH_TEST_CLIENT_ID'], os.environ['OAUTH_TEST_CLIENT_SECRET']), "
                "'binding': store.get_authority_binding(os.environ['OAUTH_TEST_CLIENT_ID'])}, sort_keys=True))"
            ),
        ],
        check=False,
        capture_output=True,
        env=env,
        text=True,
    )
    assert restarted.returncode == 0, restarted.stderr
    restarted_state = json.loads(restarted.stdout)
    assert restarted_state["client"]["owner"] == winner["owner"]
    assert restarted_state["client"]["tenant_id"] == winner["tenant_id"]
    assert restarted_state["binding"]["event_id"] == winner["authority_binding_id"]


def test_base_client_binding_rejects_scope_outside_actor_authority(isolate_oauth_clients: Path) -> None:
    secret = "scope-amplifier-secret"
    write_collection(
        db_path=isolate_oauth_clients,
        scope="identity",
        collection_name="oauth_clients",
        rows=[
            {
                "client_id": "client_scope_amplifier",
                "client_secret_hash": hashlib.sha256(secret.encode("utf-8")).hexdigest(),
                "client_name": "legacy-scope-amplifier",
                "grant_types": ["client_credentials"],
                "scope": "runtime.execute",
                "redirect_uris": [],
                "created_at": 1,
            }
        ],
    )

    with TestClient(app) as client:
        response = client.post(
            "/v1/oauth/clients/client_scope_amplifier/authority/register",
            json={"client_secret": secret},
            headers={
                "X-API-Key": "limited-oauth-key",
                "X-Tenant-ID": "tenant-a",
                "Idempotency-Key": "reject-legacy-scope-amplifier",
            },
        )

    assert response.status_code == 401
    assert OAuthClientStore(db_path=isolate_oauth_clients).get_authority_binding("client_scope_amplifier") is None
    assert query_events(event_type=EVENT_OAUTH_CLIENT_AUTHORITY_BOUND) == []


def test_store_rejects_unsupported_grants_directly(isolate_oauth_clients: Path) -> None:
    store = OAuthClientStore(db_path=isolate_oauth_clients)
    with pytest.raises(ValueError, match="unsupported grant_type"):
        store.register_client(
            client_name="unsupported-client",
            grant_types=["authorization_code"],
            scope="read",
            owner="owner-test",
            tenant_id="tenant-test",
            authorized_scopes=["read"],
        )


def test_store_rejects_scope_outside_registrar_authority(isolate_oauth_clients: Path) -> None:
    store = OAuthClientStore(db_path=isolate_oauth_clients)

    with pytest.raises(ValueError, match="requested scope exceeds registrar authority"):
        store.register_client(
            client_name="direct-scope-amplifier",
            grant_types=["client_credentials"],
            scope="read runtime.execute",
            owner="owner-test",
            tenant_id="tenant-test",
            authorized_scopes=["read"],
        )
