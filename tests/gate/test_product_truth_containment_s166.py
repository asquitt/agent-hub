from __future__ import annotations

from pathlib import Path

import fcntl
import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.persistence.singleton_guard import (
    acquire_singleton_guard,
    release_singleton_guard,
)

ROOT = Path(__file__).resolve().parents[2]


def test_every_openapi_operation_has_evidence_maturity() -> None:
    schema = TestClient(app).get("/openapi.json").json()
    assert schema["x-agenthub-production-ready"] is False
    assert "ApiKeyAuth" in schema["components"]["securitySchemes"]

    operations = []
    for path_item in schema["paths"].values():
        for method, operation in path_item.items():
            if method in {
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "options",
                "head",
                "trace",
            }:
                operations.append(operation)

    assert operations
    assert all(
        operation["x-agenthub-maturity"] in {"prototype", "stub", "deferred"}
        for operation in operations
    )
    assert all("x-agenthub-evidence-boundary" in operation for operation in operations)
    assert not any(
        operation["x-agenthub-maturity"] == "production" for operation in operations
    )
    assert (
        schema["paths"]["/v1/runtime/sandboxes/{sandbox_id}/execute"]["post"][
            "x-agenthub-maturity"
        ]
        == "stub"
    )
    assert (
        schema["paths"]["/v1/billing/invoices/generate"]["post"]["x-agenthub-maturity"]
        == "deferred"
    )


def test_public_claims_name_the_actual_product_boundary() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    marketing = (ROOT / "src/ui/marketing_home.html").read_text(encoding="utf-8")

    assert "does not yet execute remote agent workloads" in readme
    assert "Runtime State Simulator" in readme
    assert "Postgres and Redis are not connected or included" in readme
    assert "Managed Agent Runtime (`S79` through `S82`) is complete" not in readme
    assert "pytest checks" not in marketing
    assert "Production readiness is not claimed" in marketing


def test_runtime_api_marks_non_execution_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from src.runtime.storage import RUNTIME_STORAGE

    monkeypatch.setenv("AGENTHUB_RUNTIME_DB_PATH", str(tmp_path / "runtime.db"))
    RUNTIME_STORAGE.reset_for_tests(db_path=tmp_path / "runtime.db")
    client = TestClient(app)
    response = client.post(
        "/v1/runtime/sandboxes",
        json={"agent_id": "local-simulator"},
        headers={
            "X-API-Key": "dev-owner-key",
            "Idempotency-Key": "s166-runtime-simulator",
        },
    )
    assert response.status_code == 200
    assert response.json()["execution_mode"] == "state_simulation"
    assert response.json()["workload_executed"] is False
    assert response.json()["isolation_enforced"] is False


@pytest.mark.parametrize(
    "name", ["AGENTHUB_API_WORKERS", "WEB_CONCURRENCY", "AGENTHUB_API_REPLICAS"]
)
def test_declared_unsafe_sqlite_topology_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str
) -> None:
    release_singleton_guard()
    monkeypatch.setenv("AGENTHUB_SINGLETON_LOCK_PATH", str(tmp_path / "owner.lock"))
    monkeypatch.setenv(name, "2")
    with pytest.raises(RuntimeError, match="must equal 1"):
        acquire_singleton_guard()


def test_second_process_lock_owner_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    release_singleton_guard()
    path = tmp_path / "owner.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    external = path.open("a+", encoding="utf-8")
    fcntl.flock(external.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    monkeypatch.setenv("AGENTHUB_SINGLETON_LOCK_PATH", str(path))
    try:
        with pytest.raises(RuntimeError, match="another AgentHub process"):
            acquire_singleton_guard()
    finally:
        fcntl.flock(external.fileno(), fcntl.LOCK_UN)
        external.close()
        release_singleton_guard()
