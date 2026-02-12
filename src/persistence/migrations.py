from __future__ import annotations

import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_MIGRATIONS_ROOT = ROOT / "db" / "migrations" / "runtime"


def apply_scope_migrations(conn: sqlite3.Connection, scope: str) -> list[str]:
    migration_dir = RUNTIME_MIGRATIONS_ROOT / scope
    if not migration_dir.exists():
        raise FileNotFoundError(f"migration scope not found: {migration_dir}")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS _schema_migrations (
            scope TEXT NOT NULL,
            migration_name TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            PRIMARY KEY (scope, migration_name)
        )
        """
    )

    existing = {
        str(row["migration_name"])
        for row in conn.execute(
            "SELECT migration_name FROM _schema_migrations WHERE scope = ?",
            (scope,),
        )
    }

    applied: list[str] = []
    for path in sorted(migration_dir.glob("*.sql")):
        name = path.name
        if name in existing:
            continue
        script = path.read_text(encoding="utf-8")
        with conn:
            conn.executescript(script)
            conn.execute(
                "INSERT INTO _schema_migrations(scope, migration_name) VALUES (?, ?)",
                (scope, name),
            )
        applied.append(name)
    return applied
