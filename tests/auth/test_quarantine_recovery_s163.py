from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.auth import AuthContext
from src.identity import storage as identity_storage


@pytest.fixture()
def quarantine_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    identity_db = tmp_path / "identity.db"
    monkeypatch.setenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "enforce")
    monkeypatch.setenv("AGENTHUB_IDENTITY_DB_PATH", str(identity_db))
    monkeypatch.setenv(
        "AGENTHUB_API_KEYS_JSON",
        json.dumps(
            {
                "owner-a-admin": {
                    "owner": "owner-a",
                    "scopes": ["*"],
                    "roles": ["admin"],
                },
                "owner-b-admin": {
                    "owner": "owner-b",
                    "scopes": ["*"],
                    "roles": ["admin"],
                },
                "owner-a-member": {
                    "owner": "owner-a",
                    "scopes": ["*"],
                    "roles": ["member"],
                },
                "owner-a-reader": {
                    "owner": "owner-a",
                    "scopes": ["identity.read"],
                    "roles": ["admin"],
                },
            }
        ),
    )
    monkeypatch.setenv(
        "AGENTHUB_OWNER_TENANTS_JSON",
        json.dumps(
            {
                "owner-a": ["tenant-default", "tenant-a", "tenant-b"],
                "owner-b": ["tenant-a"],
            }
        ),
    )
    identity_storage.reset_for_tests(db_path=identity_db)
    return identity_db


def _headers(
    api_key: str,
    tenant_id: str | None = "tenant-a",
    *,
    idempotency_key: str | None = None,
) -> dict[str, str]:
    headers = {"X-API-Key": api_key}
    if tenant_id is not None:
        headers["X-Tenant-ID"] = tenant_id
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    return headers


def _insert_quarantined(
    agent_id: str,
    owner: str,
    *,
    tenant_id: str | None = None,
) -> None:
    storage = identity_storage.IDENTITY_STORAGE
    storage._ensure_ready()
    assert storage._conn is not None
    with storage._conn:
        storage._conn.execute(
            """
            INSERT INTO agent_identities(
                agent_id, owner, tenant_id, tenancy_status, credential_type, status
            ) VALUES (?, ?, ?, 'quarantined', 'api_key', 'active')
            """,
            (agent_id, owner, tenant_id),
        )


def _create_populated_pre_0006_database(db_path: Path) -> None:
    migration_dir = Path("db/migrations/runtime/identity")
    conn = sqlite3.connect(db_path)
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


def test_populated_pre_0006_database_requires_explicit_recovery_and_persists_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = tmp_path / "pre-0006.db"
    _create_populated_pre_0006_database(db_path)
    monkeypatch.setenv("AGENTHUB_IDENTITY_DB_PATH", str(db_path))
    storage = identity_storage.IdentityStorage()
    storage.reconfigure(db_path)
    actor = AuthContext(
        "legacy-owner",
        scopes=("*",),
        roles=("admin",),
        tenant_id="tenant-recovery",
        auth_method="api_key",
    )

    quarantined = storage.list_quarantined_identities_for_actor(actor)
    assert [identity["agent_id"] for identity in quarantined] == ["legacy-agent"]
    assert quarantined[0]["tenant_id"] is None
    with pytest.raises(ValueError, match="explicit tenant selection required"):
        storage.assign_quarantined_identity_for_actor(
            actor=actor,
            agent_id="legacy-agent",
            selected_tenant_id="",
        )

    assigned = storage.assign_quarantined_identity_for_actor(
        actor=actor,
        agent_id="legacy-agent",
        selected_tenant_id="tenant-recovery",
    )
    assert assigned["owner"] == "legacy-owner"
    assert assigned["tenant_id"] == "tenant-recovery"
    assert assigned["tenancy_status"] == "active"
    _, generation, tenant_id = storage.get_identity_auth_snapshot("legacy-agent")
    assert generation
    assert tenant_id == "tenant-recovery"

    storage.reconfigure(db_path)
    with sqlite3.connect(db_path) as restarted:
        restarted.row_factory = sqlite3.Row
        migration = restarted.execute(
            """
            SELECT 1 FROM _schema_migrations
            WHERE scope = 'identity' AND migration_name = '0007_quarantine_assignment.sql'
            """
        ).fetchone()
        audit = restarted.execute(
            """
            SELECT agent_id, owner, tenant_id, actor, assigned_at
            FROM identity_quarantine_assignments
            """
        ).fetchone()

    assert migration is not None
    assert audit is not None
    assert dict(audit) == {
        "agent_id": "legacy-agent",
        "owner": "legacy-owner",
        "tenant_id": "tenant-recovery",
        "actor": "legacy-owner",
        "assigned_at": audit["assigned_at"],
    }
    assert audit["assigned_at"]
    assert storage.count_quarantined_identities() == 0


def test_quarantine_listing_is_owner_scoped_and_admin_gated(
    quarantine_runtime: Path,
) -> None:
    _insert_quarantined("owner-a-legacy", "owner-a")
    _insert_quarantined("owner-b-legacy", "owner-b")

    with TestClient(app) as client:
        owner_a = client.get(
            "/v1/identity/quarantine",
            headers=_headers("owner-a-admin"),
        )
        owner_b = client.get(
            "/v1/identity/quarantine",
            headers=_headers("owner-b-admin"),
        )
        member = client.get(
            "/v1/identity/quarantine",
            headers=_headers("owner-a-member"),
        )

    assert owner_a.status_code == 200
    assert [item["agent_id"] for item in owner_a.json()["identities"]] == ["owner-a-legacy"]
    assert owner_b.status_code == 200
    assert [item["agent_id"] for item in owner_b.json()["identities"]] == ["owner-b-legacy"]
    assert member.status_code == 403
    assert member.json()["detail"]["code"] == "auth.admin_required"


def test_assignment_requires_admin_write_permission_and_explicit_tenant(
    quarantine_runtime: Path,
) -> None:
    _insert_quarantined("legacy-agent", "owner-a")

    with TestClient(app) as client:
        member = client.post(
            "/v1/identity/quarantine/legacy-agent/assign",
            headers=_headers(
                "owner-a-member",
                idempotency_key="member-assignment",
            ),
        )
        read_only_admin = client.post(
            "/v1/identity/quarantine/legacy-agent/assign",
            headers=_headers(
                "owner-a-reader",
                idempotency_key="reader-assignment",
            ),
        )
        omitted_tenant = client.post(
            "/v1/identity/quarantine/legacy-agent/assign",
            headers=_headers(
                "owner-a-admin",
                tenant_id=None,
                idempotency_key="missing-tenant-assignment",
            ),
        )

    assert member.status_code == 403
    assert member.json()["detail"]["code"] == "auth.admin_required"
    assert read_only_admin.status_code == 403
    assert read_only_admin.json()["detail"]["code"] == "scope.forbidden"
    assert omitted_tenant.status_code == 400
    assert omitted_tenant.json()["detail"] == "explicit X-Tenant-ID header required"
    assert identity_storage.IDENTITY_STORAGE.count_quarantined_identities() == 1


def test_assignment_rejects_missing_active_ambiguous_and_cross_owner_without_disclosure(
    quarantine_runtime: Path,
) -> None:
    _insert_quarantined("owner-b-legacy", "owner-b")
    _insert_quarantined("ambiguous-legacy", "owner-a", tenant_id="tenant-unknown")
    identity_storage.register_agent_identity_for_actor(
        actor=AuthContext(
            "owner-a",
            scopes=("*",),
            roles=("admin",),
            tenant_id="tenant-a",
            auth_method="api_key",
        ),
        agent_id="active-agent",
        credential_type="api_key",
    )

    targets = ["missing-agent", "active-agent", "ambiguous-legacy", "owner-b-legacy"]
    with TestClient(app) as client:
        responses = [
            client.post(
                f"/v1/identity/quarantine/{target}/assign",
                headers=_headers(
                    "owner-a-admin",
                    idempotency_key=f"reject-{target}",
                ),
            )
            for target in targets
        ]

    assert [response.status_code for response in responses] == [404, 404, 404, 404]
    details = [response.json()["detail"].replace(target, "<target>") for response, target in zip(responses, targets)]
    assert len(set(details)) == 1
    assert details[0] == "'quarantined identity not found: <target>'"


def test_assignment_audit_and_readiness_survive_reconfigure(
    quarantine_runtime: Path,
) -> None:
    _insert_quarantined("legacy-one", "owner-a")
    _insert_quarantined("legacy-two", "owner-a")

    with TestClient(app) as client:
        blocked = client.get("/readyz")
        first = client.post(
            "/v1/identity/quarantine/legacy-one/assign",
            headers=_headers(
                "owner-a-admin",
                tenant_id="tenant-b",
                idempotency_key="assign-legacy-one",
            ),
        )
        still_blocked = client.get("/readyz")

    assert blocked.status_code == 503
    assert blocked.json()["checks"]["identity_quarantine"] == {
        "status": "blocked",
        "quarantined_count": 2,
    }
    assert first.status_code == 200
    assert first.json()["tenant_id"] == "tenant-b"
    assert still_blocked.status_code == 503
    assert still_blocked.json()["checks"]["identity_quarantine"]["quarantined_count"] == 1

    identity_storage.reconfigure(db_path=quarantine_runtime)
    with sqlite3.connect(quarantine_runtime) as restarted:
        restarted.row_factory = sqlite3.Row
        audit = restarted.execute(
            """
            SELECT agent_id, owner, tenant_id, actor, assigned_at
            FROM identity_quarantine_assignments
            WHERE agent_id = 'legacy-one'
            """
        ).fetchone()
    assert audit is not None
    assert audit["owner"] == "owner-a"
    assert audit["tenant_id"] == "tenant-b"
    assert audit["actor"] == "owner-a"
    assert audit["assigned_at"]

    with sqlite3.connect(quarantine_runtime) as tamper_attempt:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="identity quarantine assignments are append-only",
        ):
            tamper_attempt.execute(
                """
                UPDATE identity_quarantine_assignments
                SET tenant_id = 'attacker-tenant'
                WHERE agent_id = 'legacy-one'
                """
            )
        tamper_attempt.rollback()
        with pytest.raises(
            sqlite3.IntegrityError,
            match="identity quarantine assignments are append-only",
        ):
            tamper_attempt.execute(
                """
                DELETE FROM identity_quarantine_assignments
                WHERE agent_id = 'legacy-one'
                """
            )
        tamper_attempt.rollback()

    with TestClient(app) as client:
        blocked_after_restart = client.get("/readyz")
        second = client.post(
            "/v1/identity/quarantine/legacy-two/assign",
            headers=_headers(
                "owner-a-admin",
                idempotency_key="assign-legacy-two",
            ),
        )
        recovered = client.get("/readyz")

    assert blocked_after_restart.status_code == 503
    assert blocked_after_restart.json()["checks"]["identity_quarantine"]["quarantined_count"] == 1
    assert second.status_code == 200
    assert recovered.status_code == 200
    assert recovered.json()["checks"]["identity_quarantine"] == {
        "status": "ok",
        "quarantined_count": 0,
    }
