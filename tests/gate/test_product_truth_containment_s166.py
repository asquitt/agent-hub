from __future__ import annotations

import base64
import json
from pathlib import Path

import fcntl
import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.openapi_contract import operation_maturity
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
    assert all("x-agenthub-access" in operation for operation in operations)
    assert all("security" in operation for operation in operations)
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
    relay_operations = {
        (method.upper(), path): operation
        for path, path_item in schema["paths"].items()
        if path.startswith("/v1/relay")
        for method, operation in path_item.items()
        if method in {"get", "post", "put", "patch", "delete"}
    }
    assert len(relay_operations) == 8
    for (method, path), operation in relay_operations.items():
        assert operation["x-agenthub-maturity"] == "prototype"
        assert "one operator-attested" in operation["x-agenthub-evidence-boundary"]
        if (method, path) in {
            ("GET", "/v1/relay/receipt-keys/current"),
            ("POST", "/v1/relay/receipts/verify"),
        }:
            assert operation["x-agenthub-access"] == "public"
            assert operation["security"] == []
        else:
            assert operation["x-agenthub-access"] != "public"
            assert operation["security"]
    assert {"ApiKeyAuth": []} not in relay_operations[("POST", "/v1/relay/mcp/call")][
        "security"
    ]


def test_known_simulation_and_metadata_routes_are_truthfully_stubbed() -> None:
    schema = TestClient(app).get("/openapi.json").json()

    pqc_paths = {
        path: path_item
        for path, path_item in schema["paths"].items()
        if path.startswith("/v1/identity/pqc")
    }
    assert pqc_paths
    for path_item in pqc_paths.values():
        for method, operation in path_item.items():
            if method in {"get", "post"}:
                assert operation["x-agenthub-maturity"] == "stub"
                assert (
                    "no NIST post-quantum implementation"
                    in operation["x-agenthub-evidence-boundary"]
                )

    for path in {
        "/v1/identity/agents/{agent_id}/spiffe-id",
        "/v1/identity/agents/{agent_id}/svid",
        "/v1/identity/spiffe/bundle",
        "/v1/identity/spiffe/verify",
    }:
        for method, operation in schema["paths"][path].items():
            if method in {"get", "post"}:
                assert operation["x-agenthub-maturity"] == "stub"
                assert (
                    "no SPIRE workload attestation or CA-issued X.509 SVID"
                    in operation["x-agenthub-evidence-boundary"]
                )

    authorize = schema["paths"]["/v1/oauth/authorize"]["get"]
    assert authorize["x-agenthub-maturity"] == "stub"
    assert (
        "only rejects unsupported interactive grants"
        in authorize["x-agenthub-evidence-boundary"]
    )


def test_unclassified_routes_fail_closed_without_relabeling_known_prototypes() -> None:
    for path in {
        "/v1/unclassified/new-capability",
        "/v1/agents-extra",
        "/v1/agents/unregistered-child",
        "/v1/oauth/unregistered-child",
        "/v1/federation/unregistered-child",
        "/v1/relay-shadow",
    }:
        maturity, boundary = operation_maturity("GET", path)
        assert maturity == "stub"
        assert "unclassified route" in boundary

    known_maturity, _ = operation_maturity("GET", "/v1/agents")
    assert known_maturity == "prototype"

    new_method_maturity, boundary = operation_maturity("TRACE", "/v1/agents")
    assert new_method_maturity == "stub"
    assert "unclassified route" in boundary


def test_public_claims_name_the_actual_product_boundary() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    marketing = (ROOT / "src/ui/marketing_home.html").read_text(encoding="utf-8")

    assert "only remote execution path is one operator-attested" in readme
    assert "server-declared read-only/idempotent" in readme
    assert "MCP annotations are untrusted hints" in readme
    assert "not general remote execution" in marketing
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

    sandbox_id = response.json()["sandbox_id"]
    started = client.post(
        f"/v1/runtime/sandboxes/{sandbox_id}/execute",
        json={"input_data": {"task": "record-only"}},
        headers={
            "X-API-Key": "dev-owner-key",
            "Idempotency-Key": "s166-runtime-start",
        },
    )
    assert started.status_code == 200
    completed = client.post(
        f"/v1/runtime/sandboxes/{sandbox_id}/complete",
        json={"output_data": {"caller_reported": True}},
        headers={
            "X-API-Key": "dev-owner-key",
            "Idempotency-Key": "s166-runtime-complete",
        },
    )
    assert completed.status_code == 200

    listed = client.get(
        "/v1/runtime/executions",
        headers={"X-API-Key": "dev-owner-key"},
    )
    assert listed.status_code == 200
    assert listed.json()["execution_mode"] == "state_simulation"
    assert listed.json()["workload_executed"] is False
    assert listed.json()["executions"]
    assert all(
        execution["execution_mode"] == "state_simulation"
        and execution["workload_executed"] is False
        for execution in listed.json()["executions"]
    )


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


def test_rejected_contender_cannot_reconcile_relay_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from src.relay.storage import RelayStorage

    release_singleton_guard()
    relay_path = tmp_path / "relay.db"
    lock_path = tmp_path / "owner.lock"
    store = RelayStorage()
    store.reset_for_tests(relay_path)
    store.upsert_target(
        {
            "target_id": "catalog",
            "tenant_id": "tenant-a",
            "endpoint_url": "https://mcp.example.test/mcp",
            "endpoint_digest": "endpoint-digest",
            "tool_name": "lookup",
            "server_name": "catalog",
            "server_version": "1",
            "protocol_version": "2025-11-25",
            "input_schema": {"type": "object"},
            "output_schema": {"type": "object"},
            "schema_digest": "schema-digest",
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
            },
            "operator_attests_read_only": True,
            "max_call_cost_usd": 0.25,
            "policy_revision": "policy-revision",
        }
    )
    store.set_budget(
        owner="owner-a",
        tenant_id="tenant-a",
        capability_token_id="cap-a",
        max_budget_usd=10,
    )
    invocation, _ = store.reserve_invocation(
        owner="owner-a",
        tenant_id="tenant-a",
        agent_id="agent-a",
        idempotency_key="active-call",
        request_hash="request-hash",
        target_id="catalog",
        capability_token_id="cap-a",
        input_hash="input-hash",
    )
    store.reserve_budget(
        invocation_id=invocation["invocation_id"],
        policy={"allowed": True},
        cost_usd=0.25,
    )
    store.mark_network_started(
        invocation["invocation_id"], target_snapshot=store.get_target("catalog")
    )
    store.close()

    monkeypatch.setenv("AGENTHUB_SINGLETON_LOCK_PATH", str(lock_path))
    monkeypatch.setenv("AGENTHUB_RELAY_DB_PATH", str(relay_path))
    monkeypatch.setenv(
        "AGENTHUB_MCP_RECEIPT_PRIVATE_KEY_B64",
        base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("="),
    )
    monkeypatch.setenv(
        "AGENTHUB_MCP_RELAY_TARGETS_JSON",
        json.dumps(
            [
                {
                    "target_id": "catalog",
                    "tenant_id": "tenant-a",
                    "endpoint_url": "https://mcp.example.test/mcp",
                    "tool_name": "lookup",
                    "auth": "none",
                    "operator_attests_read_only": True,
                    "max_call_cost_usd": 0.25,
                }
            ]
        ),
    )
    external = lock_path.open("a+", encoding="utf-8")
    fcntl.flock(external.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(RuntimeError, match="another AgentHub process"):
            with TestClient(app):
                pass
    finally:
        fcntl.flock(external.fileno(), fcntl.LOCK_UN)
        external.close()
        release_singleton_guard()

    reloaded = RelayStorage()
    reloaded.reconfigure(relay_path)
    assert reloaded.get_invocation_unscoped(invocation["invocation_id"])["status"] == (
        "pending"
    )
    budget = reloaded.get_budget(
        owner="owner-a", tenant_id="tenant-a", capability_token_id="cap-a"
    )
    assert budget["reserved_usd"] == 0.25
    assert budget["spent_usd"] == 0
    reloaded.close()
