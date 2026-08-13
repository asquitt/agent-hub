from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def _dockerignore_entries() -> set[str]:
    return {
        line.strip()
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def test_docker_image_installs_only_runtime_dependencies_and_one_worker() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY requirements-runtime.txt" in dockerfile
    assert "-r requirements-runtime.txt" in dockerfile
    assert '"--workers", "1"' in dockerfile
    assert '"--workers", "2"' not in dockerfile
    assert 'VOLUME ["/app/data"]' in dockerfile
    assert '--gecos "" appuser' in dockerfile
    assert "USER appuser" in dockerfile


def test_compose_is_an_explicit_single_replica_sqlite_topology() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))

    assert set(compose["services"]) == {"api"}
    api = compose["services"]["api"]
    assert api["deploy"]["replicas"] == 1
    assert "depends_on" not in api
    assert "agenthub_data:/app/data" in api["volumes"]
    assert set(compose["volumes"]) == {"agenthub_data"}

    environment = api["environment"]
    assert "DATABASE_URL" not in environment
    assert "REDIS_URL" not in environment
    for name in (
        "AGENTHUB_API_KEYS_JSON",
        "AGENTHUB_AUTH_TOKEN_SECRET",
        "AGENTHUB_IDENTITY_SIGNING_SECRET",
        "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON",
        "AGENTHUB_PROVENANCE_SIGNING_SECRET",
        "AGENTHUB_POLICY_SIGNING_SECRET",
        "AGENTHUB_VAULT_KEY",
    ):
        assert ":?" in environment[name]


def test_production_context_excludes_state_tests_and_test_requirements() -> None:
    ignored = _dockerignore_entries()

    assert {"data/", "tests/", "requirements.txt"} <= ignored
    runtime_requirements = (ROOT / "requirements-runtime.txt").read_text(encoding="utf-8").lower()
    assert "pytest" not in runtime_requirements


def test_makefile_describes_the_active_sqlite_migration_topology() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    migrate_recipe = makefile.split("migrate:", maxsplit=1)[1].split("\n\n", maxsplit=1)[0]
    assert "SQLite scope migrations run during application startup" in migrate_recipe
    assert "psql" not in migrate_recipe
