from __future__ import annotations

import sqlite3
from pathlib import Path

import yaml

from src.api.store import RegistryStore

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "specs" / "manifest" / "examples" / "simple-tool-agent.yaml"


def _manifest(version: str) -> dict:
    loaded = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    loaded["identity"]["version"] = version
    return loaded


def _backup_database(source: Path, target: Path) -> None:
    with sqlite3.connect(str(source)) as src_conn, sqlite3.connect(str(target)) as dst_conn:
        src_conn.backup(dst_conn)


def _restore_database(snapshot: Path, target: Path) -> None:
    with sqlite3.connect(str(snapshot)) as src_conn, sqlite3.connect(str(target)) as dst_conn:
        src_conn.backup(dst_conn)


def test_registry_store_applies_migrations_and_persists_across_restart(tmp_path: Path) -> None:
    db_path = tmp_path / "registry.db"
    store = RegistryStore(db_path=db_path)
    store.reset_for_tests(db_path=db_path)

    store.reserve_namespace("@persist", "owner-dev")
    created = store.register_agent("@persist", _manifest("1.0.0"), "owner-dev")

    update_manifest = _manifest("1.1.0")
    update_manifest["identity"]["id"] = created.slug
    store.update_agent(created.agent_id, update_manifest, "owner-dev")

    restarted = RegistryStore(db_path=db_path)
    restored = restarted.get_agent(created.agent_id)
    assert restored.namespace == "@persist"
    assert restored.owner == "owner-dev"
    assert [v.version for v in restored.versions] == ["1.0.0", "1.1.0"]

    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM _schema_migrations WHERE scope = 'registry' AND migration_name = '0001_registry_foundation.sql'"
        ).fetchone()
        assert row is not None
        assert int(row[0]) == 1


def test_registry_store_snapshot_restore_recovers_prior_state(tmp_path: Path) -> None:
    db_path = tmp_path / "registry.db"
    snapshot_path = tmp_path / "registry-snapshot.db"
    drain_path = tmp_path / "registry-drain.db"

    store = RegistryStore(db_path=db_path)
    store.reset_for_tests(db_path=db_path)
    store.reserve_namespace("@recover", "owner-dev")
    created = store.register_agent("@recover", _manifest("1.0.0"), "owner-dev")

    _backup_database(db_path, snapshot_path)

    store.delete_agent(created.agent_id, "owner-dev")
    assert store.get_agent(created.agent_id).status == "deprecated"

    store.reconfigure(db_path=drain_path)
    _restore_database(snapshot_path, db_path)

    recovered = RegistryStore(db_path=db_path)
    row = recovered.get_agent(created.agent_id)
    assert row.status == "active"
    assert [version.version for version in row.versions] == ["1.0.0"]
