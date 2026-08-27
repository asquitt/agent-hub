from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.auth import AuthContext
from src.identity import storage as identity_storage
from src.identity.credentials import issue_credential
from src.identity.delegation_tokens import get_delegation_chain, issue_delegation_token
from src.identity.revocation import list_revocation_events, revoke_agent
from src.registry.store import STORE


MANIFEST_PATH = Path("specs/manifest/examples/simple-tool-agent.yaml")


@pytest.fixture()
def authorization_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "enforce")
    monkeypatch.setenv(
        "AGENTHUB_API_KEYS_JSON",
        json.dumps(
            {
                "owner-a-key": {"owner": "owner-a", "scopes": ["*"], "roles": ["admin"]},
                "owner-b-key": {"owner": "owner-b", "scopes": ["*"], "roles": ["admin"]},
            }
        ),
    )
    monkeypatch.setenv(
        "AGENTHUB_OWNER_TENANTS_JSON",
        json.dumps({"owner-a": ["tenant-a", "tenant-b"], "owner-b": ["tenant-a"]}),
    )
    monkeypatch.setenv("AGENTHUB_IDENTITY_SIGNING_SECRET", "s163-object-auth-secret")
    monkeypatch.setenv("AGENTHUB_VAULT_KEY", "s163-object-vault-secret")
    identity_db = tmp_path / "identity.db"
    monkeypatch.setenv("AGENTHUB_IDENTITY_DB_PATH", str(identity_db))
    identity_storage.reset_for_tests(db_path=identity_db)
    registry_db = tmp_path / "registry.db"
    monkeypatch.setenv("AGENTHUB_REGISTRY_DB_PATH", str(registry_db))
    STORE.reset_for_tests(db_path=registry_db)

    from src.runtime.secret_vault import reset_for_tests as reset_vault_for_tests

    reset_vault_for_tests()


def _headers(api_key: str, tenant_id: str = "tenant-a") -> dict[str, str]:
    return {"X-API-Key": api_key, "X-Tenant-ID": tenant_id}


def _actor(owner: str, tenant_id: str = "tenant-a") -> AuthContext:
    return AuthContext(
        owner,
        scopes=("*",),
        roles=("admin",),
        tenant_id=tenant_id,
        auth_method="api_key",
    )


def _manifest(agent_id: str) -> dict[str, object]:
    manifest = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
    manifest["identity"]["id"] = agent_id
    manifest["identity"]["name"] = f"{agent_id}-name"
    return manifest


def _register(
    client: TestClient,
    agent_id: str,
    *,
    api_key: str = "owner-a-key",
    tenant_id: str = "tenant-a",
) -> None:
    response = client.post(
        "/v1/identity/agents",
        json={"agent_id": agent_id},
        headers=_headers(api_key, tenant_id),
    )
    assert response.status_code == 200, response.text


@pytest.mark.parametrize(
    ("denied_headers", "expected_status"),
    [
        (_headers("owner-b-key", "tenant-a"), 404),
        (_headers("owner-a-key", "tenant-b"), 404),
    ],
)
def test_scim_get_and_mutations_fail_closed_across_boundaries(
    authorization_runtime: None,
    denied_headers: dict[str, str],
    expected_status: int,
) -> None:
    with TestClient(app) as client:
        _register(client, "scim-owned-agent")

        responses = [
            client.get("/scim/v2/Users/scim-owned-agent", headers=denied_headers),
            client.put(
                "/scim/v2/Users/scim-owned-agent",
                json={"active": False},
                headers=denied_headers,
            ),
            client.patch(
                "/scim/v2/Users/scim-owned-agent",
                json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
                headers=denied_headers,
            ),
            client.delete("/scim/v2/Users/scim-owned-agent", headers=denied_headers),
        ]
        listing = client.get("/scim/v2/Users", headers=denied_headers)
        owner_read = client.get(
            "/scim/v2/Users/scim-owned-agent",
            headers=_headers("owner-a-key", "tenant-a"),
        )

    assert [response.status_code for response in responses] == [expected_status] * 4
    assert listing.status_code == 200
    assert listing.json()["Resources"] == []
    assert owner_read.status_code == 200
    assert owner_read.json()["active"] is True


@pytest.mark.parametrize(
    "denied_headers",
    [
        _headers("owner-b-key", "tenant-a"),
        _headers("owner-a-key", "tenant-b"),
    ],
)
def test_scim_bulk_cannot_mutate_cross_boundary_identity(
    authorization_runtime: None,
    denied_headers: dict[str, str],
) -> None:
    with TestClient(app) as client:
        _register(client, "bulk-owned-agent")
        response = client.post(
            "/scim/v2/Bulk",
            json={
                "Operations": [
                    {
                        "method": "PUT",
                        "path": "/Users/bulk-owned-agent",
                        "bulkId": "put",
                        "data": {"active": False},
                    },
                    {
                        "method": "PATCH",
                        "path": "/Users/bulk-owned-agent",
                        "bulkId": "patch",
                        "data": {
                            "Operations": [
                                {"op": "replace", "path": "active", "value": False}
                            ]
                        },
                    },
                    {
                        "method": "DELETE",
                        "path": "/Users/bulk-owned-agent",
                        "bulkId": "delete",
                    },
                ]
            },
            headers=denied_headers,
        )
        owner_read = client.get(
            "/scim/v2/Users/bulk-owned-agent",
            headers=_headers("owner-a-key", "tenant-a"),
        )

    assert response.status_code == 200
    assert [operation["status"] for operation in response.json()["Operations"]] == [
        "404",
        "404",
        "404",
    ]
    assert owner_read.status_code == 200
    assert owner_read.json()["active"] is True


def test_populated_legacy_database_is_explicitly_quarantined(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "legacy-identity.db"
    migration_dir = Path("db/migrations/runtime/identity")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE _schema_migrations (
            scope TEXT NOT NULL,
            migration_name TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            PRIMARY KEY (scope, migration_name)
        )
        """
    )
    for name in (
        "0001_identity_foundation.sql",
        "0002_delegation_tokens.sql",
        "0003_revocation_events.sql",
        "0004_trust_registry.sql",
        "0005_blended_identity.sql",
    ):
        conn.executescript((migration_dir / name).read_text(encoding="utf-8"))
        conn.execute(
            "INSERT INTO _schema_migrations(scope, migration_name) VALUES ('identity', ?)",
            (name,),
        )
    conn.execute(
        """
        INSERT INTO agent_identities(agent_id, owner, credential_type, status)
        VALUES ('legacy-agent', 'legacy-owner', 'api_key', 'active')
        """
    )
    conn.commit()
    conn.close()

    monkeypatch.setenv("AGENTHUB_IDENTITY_DB_PATH", str(db_path))
    storage = identity_storage.IdentityStorage()
    storage.reconfigure(db_path)
    with sqlite3.connect(db_path) as migrated:
        migrated.row_factory = sqlite3.Row
        legacy = migrated.execute(
            "SELECT tenant_id, tenancy_status FROM agent_identities WHERE agent_id = 'legacy-agent'"
        ).fetchone()
        migration = migrated.execute(
            """
            SELECT 1 FROM _schema_migrations
            WHERE scope = 'identity' AND migration_name = '0006_resource_authorization.sql'
            """
        ).fetchone()

    assert legacy is not None
    assert legacy["tenant_id"] is None
    assert legacy["tenancy_status"] == "quarantined"
    assert migration is not None
    with pytest.raises(KeyError):
        storage.get_identity("legacy-agent")
    with pytest.raises(KeyError):
        storage.get_identity_for_actor("legacy-agent", _actor("legacy-owner"))

    registered = storage.register_identity_for_actor(
        actor=_actor("legacy-owner"),
        agent_id="assigned-agent",
        credential_type="api_key",
    )
    assert registered["tenant_id"] == "tenant-a"
    assert registered["tenancy_status"] == "active"


def test_delegation_chain_is_owner_and_tenant_authorized(
    authorization_runtime: None,
) -> None:
    owner_a = _actor("owner-a")
    with TestClient(app) as client:
        _register(client, "issuer")
        _register(client, "delegate")
        issue_credential(agent_id="issuer", scopes=["read"], owner=owner_a)
        token = issue_delegation_token(
            issuer_agent_id="issuer",
            subject_agent_id="delegate",
            delegated_scopes=["read"],
            actor=owner_a,
        )
        allowed = client.get(
            f"/v1/identity/delegation-tokens/{token['token_id']}/chain",
            headers=_headers("owner-a-key", "tenant-a"),
        )
        cross_owner = client.get(
            f"/v1/identity/delegation-tokens/{token['token_id']}/chain",
            headers=_headers("owner-b-key", "tenant-a"),
        )
        cross_tenant = client.get(
            f"/v1/identity/delegation-tokens/{token['token_id']}/chain",
            headers=_headers("owner-a-key", "tenant-b"),
        )
        tree = client.get(
            f"/v1/chain-viz/tokens/{token['token_id']}/tree",
            headers=_headers("owner-a-key", "tenant-a"),
        )
        cross_owner_tree = client.get(
            f"/v1/chain-viz/tokens/{token['token_id']}/tree",
            headers=_headers("owner-b-key", "tenant-a"),
        )
        cross_tenant_tree = client.get(
            f"/v1/chain-viz/tokens/{token['token_id']}/tree",
            headers=_headers("owner-a-key", "tenant-b"),
        )
        snapshot = client.post(
            f"/v1/chain-viz/tokens/{token['token_id']}/snapshot",
            headers=_headers("owner-a-key", "tenant-a"),
        )
        assert snapshot.status_code == 200, snapshot.text
        snapshot_id = snapshot.json()["snapshot_id"]
        cross_owner_snapshot = client.get(
            f"/v1/chain-viz/snapshots/{snapshot_id}",
            headers=_headers("owner-b-key", "tenant-a"),
        )
        cross_tenant_snapshots = client.get(
            "/v1/chain-viz/snapshots",
            headers=_headers("owner-a-key", "tenant-b"),
        )

    assert allowed.status_code == 200
    assert cross_owner.status_code == 404
    assert cross_tenant.status_code == 404
    assert tree.status_code == 200
    assert cross_owner_tree.status_code == 404
    assert cross_tenant_tree.status_code == 404
    assert cross_owner_snapshot.status_code == 404
    assert cross_tenant_snapshots.json() == {"snapshots": [], "count": 0}
    with pytest.raises(KeyError):
        get_delegation_chain(token["token_id"], actor=_actor("owner-b"))
    with pytest.raises(KeyError):
        get_delegation_chain(token["token_id"], actor=_actor("owner-a", "tenant-b"))


def test_agent_principal_can_delegate_only_from_itself_to_same_tenant_peer(
    authorization_runtime: None,
) -> None:
    owner_a = _actor("owner-a")
    for agent_id in ("agent-issuer", "agent-peer"):
        identity_storage.register_agent_identity_for_actor(
            actor=owner_a,
            agent_id=agent_id,
            credential_type="api_key",
        )
    identity_storage.register_agent_identity_for_actor(
        actor=_actor("owner-a", "tenant-b"),
        agent_id="other-tenant-peer",
        credential_type="api_key",
    )
    issue_credential(agent_id="agent-issuer", scopes=["read"], owner=owner_a)
    agent_actor = AuthContext(
        "owner-a",
        scopes=("read",),
        roles=("member",),
        tenant_id="tenant-a",
        auth_method="agent_credential",
        agent_id="agent-issuer",
    )

    token = issue_delegation_token(
        issuer_agent_id="agent-issuer",
        subject_agent_id="agent-peer",
        delegated_scopes=["read"],
        actor=agent_actor,
    )
    assert token["subject_agent_id"] == "agent-peer"
    with pytest.raises(KeyError):
        issue_delegation_token(
            issuer_agent_id="agent-issuer",
            subject_agent_id="other-tenant-peer",
            delegated_scopes=["read"],
            actor=agent_actor,
        )
    with pytest.raises(KeyError):
        issue_delegation_token(
            issuer_agent_id="agent-peer",
            subject_agent_id="agent-issuer",
            delegated_scopes=["read"],
            actor=agent_actor,
        )


def test_real_delegation_token_cannot_write_registry_across_tenants(
    authorization_runtime: None,
) -> None:
    owner_a = _actor("owner-a")
    identity_storage.register_agent_identity_for_actor(
        actor=owner_a,
        agent_id="registry-issuer",
        credential_type="api_key",
    )
    identity_storage.register_agent_identity_for_actor(
        actor=owner_a,
        agent_id="registry-worker",
        credential_type="api_key",
    )
    issue_credential(agent_id="registry-issuer", scopes=["write"], owner=owner_a)
    token = issue_delegation_token(
        issuer_agent_id="registry-issuer",
        subject_agent_id="registry-worker",
        delegated_scopes=["write"],
        actor=owner_a,
    )
    delegation_headers = {"X-Delegation-Token": token["signed_token"]}

    with TestClient(app) as client:
        allowed = client.post(
            "/v1/agents",
            json={"namespace": "@tenant-a", "manifest": _manifest("allowed-registry-agent")},
            headers={
                **delegation_headers,
                "X-Tenant-ID": "tenant-a",
                "Idempotency-Key": "delegated-registry-write-tenant-a",
            },
        )
        denied = client.post(
            "/v1/agents",
            json={"namespace": "@tenant-b", "manifest": _manifest("blocked-registry-agent")},
            headers={
                **delegation_headers,
                "X-Tenant-ID": "tenant-b",
                "Idempotency-Key": "delegated-registry-write-tenant-b",
            },
        )
        tenant_b = client.get(
            "/v1/agents",
            headers=_headers("owner-a-key", "tenant-b"),
        )

    assert allowed.status_code == 200, allowed.text
    assert denied.status_code == 401, denied.text
    assert denied.json()["detail"]["code"] == "auth.required"
    assert tenant_b.status_code == 200, tenant_b.text
    assert tenant_b.json()["data"] == []


def test_tenantless_legacy_delegation_record_fails_closed(
    authorization_runtime: None,
) -> None:
    owner_a = _actor("owner-a")
    identity_storage.register_agent_identity_for_actor(
        actor=owner_a,
        agent_id="legacy-issuer",
        credential_type="api_key",
    )
    identity_storage.register_agent_identity_for_actor(
        actor=owner_a,
        agent_id="legacy-subject",
        credential_type="api_key",
    )
    identity_storage.IDENTITY_STORAGE._ensure_ready()
    conn = identity_storage.IDENTITY_STORAGE._conn
    assert conn is not None
    conn.execute(
        """
        INSERT INTO delegation_tokens(
            token_id, issuer_agent_id, subject_agent_id, delegated_scopes_json,
            issued_at_epoch, expires_at_epoch, chain_depth
        ) VALUES ('legacy-token', 'legacy-issuer', 'legacy-subject', '["read"]', 1, 9999999999, 0)
        """
    )
    conn.commit()

    with pytest.raises(PermissionError, match="attribution is missing"):
        get_delegation_chain("legacy-token", actor=owner_a)


def test_revocation_query_filters_actor_before_limit(
    authorization_runtime: None,
) -> None:
    owner_a = _actor("owner-a")
    identity_storage.register_agent_identity_for_actor(
        actor=owner_a,
        agent_id="revoked-owner-a-agent",
        credential_type="api_key",
    )
    revoke_agent(
        agent_id="revoked-owner-a-agent",
        actor=owner_a,
        reason="owner-a-event",
    )

    conn = identity_storage.IDENTITY_STORAGE._conn
    assert conn is not None
    for index in range(101):
        conn.execute(
            """
            INSERT INTO revocation_events(
                event_id, revoked_type, revoked_id, agent_id, reason, actor,
                cascade_count, owner, tenant_id, created_at
            ) VALUES (?, 'agent_identity', ?, ?, 'noise', 'owner-b', 0, 'owner-b', 'tenant-a', ?)
            """,
            (
                f"noise-{index:03d}",
                f"noise-agent-{index:03d}",
                f"noise-agent-{index:03d}",
                f"2099-01-01T00:00:{index % 60:02d}.000Z",
            ),
        )
    conn.commit()

    events = list_revocation_events(actor=owner_a, limit=100)
    assert len(events) == 1
    assert events[0]["reason"] == "owner-a-event"
    assert events[0]["owner"] == "owner-a"
    assert events[0]["tenant_id"] == "tenant-a"


def test_vault_rejects_invalid_agent_bindings(
    authorization_runtime: None,
) -> None:
    with TestClient(app) as client:
        _register(client, "owner-a-agent")
        _register(client, "owner-b-agent", api_key="owner-b-key")
        _register(client, "tenant-b-agent", tenant_id="tenant-b")

        def store(agent_id: str):
            return client.post(
                "/v1/vault/secrets",
                json={"name": f"secret-{agent_id}", "value": "value", "agent_id": agent_id},
                headers=_headers("owner-a-key", "tenant-a"),
            )

        allowed = store("owner-a-agent")
        cross_owner = store("owner-b-agent")
        cross_tenant = store("tenant-b-agent")
        missing = store("missing-agent")

    assert allowed.status_code == 200
    assert cross_owner.status_code == 404
    assert cross_tenant.status_code == 404
    assert missing.status_code == 404


def test_vault_access_rejects_invalid_agent_attribution(
    authorization_runtime: None,
) -> None:
    with TestClient(app) as client:
        _register(client, "access-owner-a-agent")
        _register(client, "access-owner-b-agent", api_key="owner-b-key")
        _register(client, "access-tenant-b-agent", tenant_id="tenant-b")
        stored = client.post(
            "/v1/vault/secrets",
            json={"name": "unbound-access-secret", "value": "value"},
            headers=_headers("owner-a-key", "tenant-a"),
        )
        assert stored.status_code == 200, stored.text
        secret_id = stored.json()["secret_id"]

        def access(agent_id: str):
            return client.post(
                f"/v1/vault/secrets/{secret_id}/access",
                json={"agent_id": agent_id},
                headers=_headers("owner-a-key", "tenant-a"),
            )

        allowed = access("access-owner-a-agent")
        cross_owner = access("access-owner-b-agent")
        cross_tenant = access("access-tenant-b-agent")
        missing = access("missing-access-agent")
        detail = client.get(
            f"/v1/vault/secrets/{secret_id}",
            headers=_headers("owner-a-key", "tenant-a"),
        )

    assert allowed.status_code == 200
    assert cross_owner.status_code == 404
    assert cross_tenant.status_code == 404
    assert missing.status_code == 404
    assert detail.status_code == 200
    assert detail.json()["access_count"] == 1
