from __future__ import annotations

import base64
from collections.abc import Callable
from pathlib import Path
import threading
import time
from typing import Any

import pytest

from src.api.auth import AuthContext
from src.protocol.mcp_client import MCPToolContractDriftError, MCPToolListingError
from src.relay.receipts import receipt_public_jwk, verify_receipt
from src.relay.service import (
    RelayCrashAfterRemoteResult,
    RelayService,
    RelayServiceError,
)
from src.relay.storage import RelayStorage


class FakeTransport:
    def __init__(self) -> None:
        self.inspect_count = 0
        self.call_count = 0
        self.failure: Exception | None = None
        self.inspect_failure: Exception | None = None
        self.during_discovery: Callable[[], None] | None = None
        self.invoke_before_dispatch = True
        self.inspection: dict[str, Any] | None = None

    async def inspect(self, target: dict[str, Any]) -> dict[str, Any]:
        self.inspect_count += 1
        if self.inspect_failure is not None:
            raise self.inspect_failure
        return self.inspection or {
            "server_name": "catalog-server",
            "server_version": "1.0.0",
            "protocol_version": "2025-11-25",
            "tool": {
                "name": target["tool_name"],
                "input_schema": {
                    "type": "object",
                    "properties": {"q": {"type": "string"}},
                    "required": ["q"],
                    "additionalProperties": False,
                },
                "output_schema": {
                    "type": "object",
                    "properties": {"answer": {"type": "string"}},
                    "required": ["answer"],
                    "additionalProperties": False,
                },
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                },
            },
        }

    async def call(
        self,
        target: dict[str, Any],
        *,
        arguments: dict[str, Any],
        before_dispatch: Callable[[], None],
        expected_schema_digest: str,
    ) -> dict[str, Any]:
        if self.during_discovery is not None:
            self.during_discovery()
        if self.failure is not None and bool(
            getattr(self.failure, "definite_failure", False)
        ):
            raise self.failure
        if self.invoke_before_dispatch:
            before_dispatch()
            self.call_count += 1
        if self.failure is not None:
            raise self.failure
        return {
            "schema_digest": expected_schema_digest,
            "is_error": False,
            "structured_content": {"answer": f"found:{arguments['q']}"},
        }


def _config(_target_id: str) -> dict[str, Any]:
    return {
        "target_id": "catalog",
        "tenant_id": "tenant-a",
        "endpoint_url": "https://mcp.example/mcp",
        "endpoint_digest": "endpoint-digest",
        "tool_name": "lookup",
        "operator_attests_read_only": True,
        "max_call_cost_usd": 0.25,
    }


def _context(*, admin: bool = False, agent_id: str = "agent-a") -> AuthContext:
    return AuthContext(
        "owner-a",
        scopes=["*" if admin else "relay.call"],
        roles=["admin" if admin else "member"],
        tenant_id="tenant-a",
        auth_method="api_key" if admin else "agent_credential",
        agent_id=None if admin else agent_id,
    )


@pytest.fixture()
def relay_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[RelayService, RelayStorage, FakeTransport]:
    seed = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    monkeypatch.setenv("AGENTHUB_MCP_RECEIPT_PRIVATE_KEY_B64", seed)
    store = RelayStorage()
    store.reset_for_tests(tmp_path / "relay.db")
    transport = FakeTransport()
    service = RelayService(transport=transport, config_loader=_config, storage=store)
    return service, store, transport


def _valid_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "src.relay.service.verify_capability_token",
        lambda *_args, **_kwargs: {
            "valid": True,
            "token_id": "cap-a",
            "issuer": "agent-a",
            "subject": "agent-a",
            "audience": "agenthub://mcp-relay",
            "resource": "urn:agenthub:mcp-relay:catalog:lookup",
            "effective_scopes": ["mcp.tools.lookup.invoke"],
        },
    )


async def _prepare(
    service: RelayService, store: RelayStorage, monkeypatch: pytest.MonkeyPatch
) -> None:
    _valid_capability(monkeypatch)
    await service.import_target("catalog", actor=_context(admin=True))
    store.set_budget(
        owner="owner-a",
        tenant_id="tenant-a",
        capability_token_id="cap-a",
        max_budget_usd=10.0,
    )


@pytest.mark.anyio
async def test_governed_call_succeeds_once_and_replays_stored_receipt(
    relay_runtime: tuple[RelayService, RelayStorage, FakeTransport],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, store, transport = relay_runtime
    await _prepare(service, store, monkeypatch)

    first = await service.invoke(
        target_id="catalog",
        capability_token={"token_id": "cap-a"},
        arguments={"q": "invoice"},
        idempotency_key="same-key",
        source_ip="127.0.0.1",
        reauthenticate=_context,
    )
    replay = await service.invoke(
        target_id="catalog",
        capability_token={"token_id": "cap-a"},
        arguments={"q": "invoice"},
        idempotency_key="same-key",
        source_ip="127.0.0.1",
        reauthenticate=_context,
    )

    assert first["status"] == "succeeded"
    assert first["result"] == {"answer": "found:invoice"}
    assert replay["idempotent_replay"] is True
    assert replay["receipt"] == first["receipt"]
    assert transport.call_count == 1

    assert verify_receipt(first["receipt"], receipt_public_jwk())["valid"] is True

    with pytest.raises(RelayServiceError) as cross_agent_replay:
        await service.invoke(
            target_id="catalog",
            capability_token={"token_id": "cap-a"},
            arguments={"q": "invoice"},
            idempotency_key="same-key",
            source_ip="127.0.0.1",
            reauthenticate=lambda: _context(agent_id="agent-b"),
        )
    assert cross_agent_replay.value.code == "relay.idempotency_conflict"
    assert transport.call_count == 1

    with pytest.raises(KeyError):
        service.get_invocation(
            first["invocation_id"], actor=_context(agent_id="agent-b")
        )
    assert (
        service.get_invocation(first["invocation_id"], actor=_context(admin=True))[
            "invocation_id"
        ]
        == first["invocation_id"]
    )


@pytest.mark.anyio
async def test_wildcard_only_capability_is_denied_before_dispatch(
    relay_runtime: tuple[RelayService, RelayStorage, FakeTransport],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, store, transport = relay_runtime
    await service.import_target("catalog", actor=_context(admin=True))
    store.set_budget(
        owner="owner-a",
        tenant_id="tenant-a",
        capability_token_id="cap-a",
        max_budget_usd=10.0,
    )
    monkeypatch.setattr(
        "src.relay.service.verify_capability_token",
        lambda *_args, **_kwargs: {
            "valid": True,
            "token_id": "cap-a",
            "issuer": "agent-a",
            "subject": "agent-a",
            "audience": "agenthub://mcp-relay",
            "resource": "urn:agenthub:mcp-relay:catalog:lookup",
            "effective_scopes": ["*"],
        },
    )

    with pytest.raises(RelayServiceError) as denied:
        await service.invoke(
            target_id="catalog",
            capability_token={"token_id": "cap-a"},
            arguments={"q": "invoice"},
            idempotency_key="wildcard-only",
            source_ip="127.0.0.1",
            reauthenticate=_context,
        )

    assert denied.value.code == "relay.policy_denied"
    assert denied.value.record is not None
    assert denied.value.record["network_started_at"] is None
    assert denied.value.record["policy"]["violated_constraints"] == [
        "relay.capability_scope_denied"
    ]
    assert transport.call_count == 0
    budget = store.get_budget(
        owner="owner-a", tenant_id="tenant-a", capability_token_id="cap-a"
    )
    assert budget["reserved_usd"] == 0
    assert budget["spent_usd"] == 0


@pytest.mark.anyio
async def test_import_maps_upstream_and_contract_failures_to_stable_errors(
    relay_runtime: tuple[RelayService, RelayStorage, FakeTransport],
) -> None:
    service, _store, transport = relay_runtime
    transport.failure = None

    async def unavailable(_target: dict[str, Any]) -> dict[str, Any]:
        raise TimeoutError("not reachable")

    transport.inspect = unavailable  # type: ignore[method-assign]
    with pytest.raises(RelayServiceError) as unavailable_error:
        await service.import_target("catalog", actor=_context(admin=True))
    assert unavailable_error.value.code == "relay.upstream_unavailable"
    assert unavailable_error.value.status_code == 502

    async def malformed(_target: dict[str, Any]) -> dict[str, Any]:
        return {"tool": {"name": "lookup", "annotations": None}}

    transport.inspect = malformed  # type: ignore[method-assign]
    with pytest.raises(RelayServiceError) as malformed_error:
        await service.import_target("catalog", actor=_context(admin=True))
    assert malformed_error.value.code == "relay.tool_contract_invalid"
    assert malformed_error.value.status_code == 409


@pytest.mark.anyio
async def test_malformed_tool_pagination_prevents_target_import(
    relay_runtime: tuple[RelayService, RelayStorage, FakeTransport],
) -> None:
    service, store, transport = relay_runtime
    transport.inspect_failure = MCPToolListingError(
        "MCP tool discovery repeated a pagination cursor before tools/call"
    )

    with pytest.raises(RelayServiceError) as exc_info:
        await service.import_target("catalog", actor=_context(admin=True))

    assert exc_info.value.code == "relay.upstream_tool_listing_invalid"
    assert exc_info.value.status_code == 502
    assert str(exc_info.value) == "configured upstream MCP tool listing was rejected"
    assert transport.inspect_count == 1
    with pytest.raises(KeyError):
        store.get_target("catalog")


@pytest.mark.anyio
async def test_malformed_tool_pagination_is_failed_uncharged_before_dispatch(
    relay_runtime: tuple[RelayService, RelayStorage, FakeTransport],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, store, transport = relay_runtime
    await _prepare(service, store, monkeypatch)
    transport.failure = MCPToolListingError(
        "MCP tool discovery repeated a pagination cursor before tools/call"
    )

    with pytest.raises(RelayServiceError) as exc_info:
        await service.invoke(
            target_id="catalog",
            capability_token={"token_id": "cap-a"},
            arguments={"q": "invoice"},
            idempotency_key="invalid-pagination",
            source_ip=None,
            reauthenticate=_context,
        )

    assert exc_info.value.code == "relay.upstream_tool_listing_invalid"
    assert exc_info.value.record is not None
    assert exc_info.value.record["status"] == "failed"
    assert exc_info.value.record["network_started_at"] is None
    assert exc_info.value.record["remote_result_observed"] is False
    assert exc_info.value.record["charged_cost_usd"] == 0
    assert transport.call_count == 0
    budget = store.get_budget(
        owner="owner-a", tenant_id="tenant-a", capability_token_id="cap-a"
    )
    assert budget["reserved_usd"] == 0
    assert budget["spent_usd"] == 0


@pytest.mark.anyio
async def test_authority_change_before_network_fails_and_releases_budget(
    relay_runtime: tuple[RelayService, RelayStorage, FakeTransport],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, store, transport = relay_runtime
    await _prepare(service, store, monkeypatch)
    calls = 0

    def reauthenticate() -> AuthContext:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise PermissionError("revoked")
        return _context()

    with pytest.raises(RelayServiceError) as exc_info:
        await service.invoke(
            target_id="catalog",
            capability_token={"token_id": "cap-a"},
            arguments={"q": "invoice"},
            idempotency_key="revoked-key",
            source_ip=None,
            reauthenticate=reauthenticate,
        )

    assert exc_info.value.code == "relay.authority_revoked"
    assert exc_info.value.record is not None
    assert exc_info.value.record["network_started_at"] is None
    assert transport.call_count == 0
    budget = store.get_budget(
        owner="owner-a", tenant_id="tenant-a", capability_token_id="cap-a"
    )
    assert budget["reserved_usd"] == 0
    assert budget["spent_usd"] == 0


@pytest.mark.anyio
async def test_revocation_during_discovery_denies_final_dispatch_and_releases_budget(
    relay_runtime: tuple[RelayService, RelayStorage, FakeTransport],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, store, transport = relay_runtime
    await _prepare(service, store, monkeypatch)
    revoked = False

    def revoke_during_discovery() -> None:
        nonlocal revoked
        revoked = True

    def reauthenticate() -> AuthContext:
        if revoked:
            raise PermissionError("revoked during discovery")
        return _context()

    transport.during_discovery = revoke_during_discovery
    with pytest.raises(RelayServiceError) as exc_info:
        await service.invoke(
            target_id="catalog",
            capability_token={"token_id": "cap-a"},
            arguments={"q": "invoice"},
            idempotency_key="revoked-during-discovery",
            source_ip=None,
            reauthenticate=reauthenticate,
        )

    assert exc_info.value.code == "relay.authority_revoked"
    assert exc_info.value.record is not None
    assert exc_info.value.record["status"] == "failed"
    assert exc_info.value.record["network_started_at"] is None
    assert exc_info.value.record["remote_result_observed"] is False
    assert exc_info.value.record["charged_cost_usd"] == 0
    assert transport.call_count == 0
    budget = store.get_budget(
        owner="owner-a", tenant_id="tenant-a", capability_token_id="cap-a"
    )
    assert budget["reserved_usd"] == 0
    assert budget["spent_usd"] == 0


@pytest.mark.anyio
async def test_transport_return_without_dispatch_callback_fails_closed(
    relay_runtime: tuple[RelayService, RelayStorage, FakeTransport],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, store, transport = relay_runtime
    await _prepare(service, store, monkeypatch)
    transport.invoke_before_dispatch = False

    with pytest.raises(RelayServiceError) as exc_info:
        await service.invoke(
            target_id="catalog",
            capability_token={"token_id": "cap-a"},
            arguments={"q": "invoice"},
            idempotency_key="missing-dispatch-admission",
            source_ip=None,
            reauthenticate=_context,
        )

    assert exc_info.value.code == "relay.transport_dispatch_not_admitted"
    assert exc_info.value.record is not None
    assert exc_info.value.record["status"] == "failed"
    assert exc_info.value.record["network_started_at"] is None
    assert exc_info.value.record["charged_cost_usd"] == 0
    assert transport.call_count == 0
    budget = store.get_budget(
        owner="owner-a", tenant_id="tenant-a", capability_token_id="cap-a"
    )
    assert budget["reserved_usd"] == 0
    assert budget["spent_usd"] == 0


@pytest.mark.anyio
async def test_concurrent_budget_reduction_cannot_cross_final_admission(
    relay_runtime: tuple[RelayService, RelayStorage, FakeTransport],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, store, _transport = relay_runtime
    await _prepare(service, store, monkeypatch)
    monkeypatch.setattr(
        "src.relay.service.get_capability_token",
        lambda *_args, **_kwargs: {"token_id": "cap-a"},
    )
    mutation_started = threading.Event()
    mutation_finished = threading.Event()
    auth_calls = 0

    def lower_budget() -> None:
        mutation_started.set()
        service.set_budget(
            capability_token_id="cap-a",
            max_budget_usd=0.1,
            actor=_context(admin=True),
        )
        mutation_finished.set()

    budget_thread = threading.Thread(target=lower_budget)

    def reauthenticate() -> AuthContext:
        nonlocal auth_calls
        auth_calls += 1
        if auth_calls == 2:
            budget_thread.start()
            assert mutation_started.wait(timeout=1)
            time.sleep(0.05)
            assert mutation_finished.is_set() is False
        return _context()

    record = await service.invoke(
        target_id="catalog",
        capability_token={"token_id": "cap-a"},
        arguments={"q": "invoice"},
        idempotency_key="budget-race",
        source_ip=None,
        reauthenticate=reauthenticate,
    )
    budget_thread.join(timeout=1)

    assert record["status"] == "succeeded"
    assert record["receipt"]["payload"]["budget"]["max_budget_usd"] == 10.0
    assert mutation_finished.is_set() is True
    assert (
        store.get_budget(
            owner="owner-a", tenant_id="tenant-a", capability_token_id="cap-a"
        )["max_budget_usd"]
        == 0.1
    )


def test_budget_mutation_requires_admin_at_the_service_boundary(
    relay_runtime: tuple[RelayService, RelayStorage, FakeTransport],
) -> None:
    service, _store, _transport = relay_runtime
    with pytest.raises(RelayServiceError) as denied:
        service.set_budget(
            capability_token_id="cap-a",
            max_budget_usd=10,
            actor=_context(),
        )
    assert denied.value.code == "relay.admin_required"


@pytest.mark.anyio
async def test_crash_after_remote_result_recovers_indeterminate_and_never_replays(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    monkeypatch.setenv("AGENTHUB_MCP_RECEIPT_PRIVATE_KEY_B64", seed)
    store = RelayStorage()
    store.reset_for_tests(tmp_path / "relay.db")
    transport = FakeTransport()

    def crash(_result: dict[str, Any]) -> None:
        raise RelayCrashAfterRemoteResult()

    crashing = RelayService(
        transport=transport,
        config_loader=_config,
        storage=store,
        after_remote_result=crash,
    )
    await _prepare(crashing, store, monkeypatch)
    with pytest.raises(RelayCrashAfterRemoteResult):
        await crashing.invoke(
            target_id="catalog",
            capability_token={"token_id": "cap-a"},
            arguments={"q": "invoice"},
            idempotency_key="crash-key",
            source_ip=None,
            reauthenticate=_context,
        )
    assert transport.call_count == 1

    recovered_service = RelayService(
        transport=transport, config_loader=_config, storage=store
    )
    recovered = recovered_service.reconcile_abandoned()
    assert recovered[0]["status"] == "indeterminate"
    assert (
        verify_receipt(recovered[0]["receipt"], receipt_public_jwk())["valid"] is True
    )
    with pytest.raises(RelayServiceError) as exc_info:
        await recovered_service.invoke(
            target_id="catalog",
            capability_token={"token_id": "cap-a"},
            arguments={"q": "invoice"},
            idempotency_key="crash-key",
            source_ip=None,
            reauthenticate=_context,
        )
    assert exc_info.value.code == "relay.replay_blocked"
    assert transport.call_count == 1


@pytest.mark.anyio
async def test_restart_signs_terminal_recovery_left_without_receipt(
    relay_runtime: tuple[RelayService, RelayStorage, FakeTransport],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, store, _transport = relay_runtime
    await _prepare(service, store, monkeypatch)
    invocation, created = store.reserve_invocation(
        owner="owner-a",
        tenant_id="tenant-a",
        agent_id="agent-a",
        idempotency_key="second-crash",
        request_hash="request-hash",
        target_id="catalog",
        capability_token_id="cap-a",
        input_hash="input-hash",
    )
    assert created is True
    store.reserve_budget(
        invocation_id=invocation["invocation_id"],
        policy={"allowed": True},
        cost_usd=0.25,
    )
    original_target = store.get_target("catalog")
    store.mark_network_started(
        invocation["invocation_id"], target_snapshot=original_target
    )
    store.upsert_target(
        {
            **original_target,
            "server_name": "replacement-server",
            "schema_digest": "replacement-schema",
            "policy_revision": "replacement-policy",
        }
    )

    interrupted = store.recover_abandoned()
    assert interrupted[0]["status"] == "indeterminate"
    assert interrupted[0]["receipt"] == {}

    restarted = RelayService(
        transport=FakeTransport(), config_loader=_config, storage=store
    )
    reconciled = restarted.reconcile_abandoned()
    assert len(reconciled) == 1
    assert reconciled[0]["receipt"]
    assert verify_receipt(reconciled[0]["receipt"], receipt_public_jwk())["valid"]
    assert reconciled[0]["receipt"]["payload"]["server_name"] == "catalog-server"
    assert (
        reconciled[0]["receipt"]["payload"]["schema_digest"]
        == original_target["schema_digest"]
    )
    assert restarted.reconcile_abandoned() == []


@pytest.mark.anyio
async def test_restart_signs_pre_dispatch_recovery_once(
    relay_runtime: tuple[RelayService, RelayStorage, FakeTransport],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, store, _transport = relay_runtime
    await _prepare(service, store, monkeypatch)
    original_target = store.get_target("catalog")
    invocation, created = store.reserve_invocation(
        owner="owner-a",
        tenant_id="tenant-a",
        agent_id="agent-a",
        idempotency_key="pre-dispatch-crash",
        request_hash="request-hash",
        target_id="catalog",
        capability_token_id="cap-a",
        input_hash="input-hash",
    )
    assert created is True
    assert invocation["target_snapshot"] == original_target

    restarted = RelayService(
        transport=FakeTransport(), config_loader=_config, storage=store
    )
    reconciled = restarted.reconcile_abandoned()
    assert len(reconciled) == 1
    assert reconciled[0]["status"] == "failed"
    assert reconciled[0]["error_code"] == "relay.recovered_before_dispatch"
    assert reconciled[0]["receipt"]
    assert verify_receipt(reconciled[0]["receipt"], receipt_public_jwk())["valid"]
    assert reconciled[0]["receipt"]["payload"]["server_name"] == "catalog-server"
    assert restarted.reconcile_abandoned() == []


@pytest.mark.anyio
async def test_invalid_input_and_transport_ambiguity_have_distinct_outcomes(
    relay_runtime: tuple[RelayService, RelayStorage, FakeTransport],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, store, transport = relay_runtime
    await _prepare(service, store, monkeypatch)
    with pytest.raises(RelayServiceError) as invalid:
        await service.invoke(
            target_id="catalog",
            capability_token={"token_id": "cap-a"},
            arguments={"wrong": True},
            idempotency_key="invalid-key",
            source_ip=None,
            reauthenticate=_context,
        )
    assert invalid.value.code == "relay.input_schema_denied"
    assert invalid.value.record is not None
    assert invalid.value.record["status"] == "failed"
    assert transport.call_count == 0

    transport.failure = TimeoutError("response lost")
    with pytest.raises(RelayServiceError) as ambiguous:
        await service.invoke(
            target_id="catalog",
            capability_token={"token_id": "cap-a"},
            arguments={"q": "invoice"},
            idempotency_key="timeout-key",
            source_ip=None,
            reauthenticate=_context,
        )
    assert ambiguous.value.code == "relay.upstream_indeterminate"
    assert ambiguous.value.record is not None
    assert ambiguous.value.record["status"] == "indeterminate"
    assert transport.call_count == 1
    budget = store.get_budget(
        owner="owner-a", tenant_id="tenant-a", capability_token_id="cap-a"
    )
    assert budget["spent_usd"] == 0.25


@pytest.mark.anyio
async def test_contract_drift_is_definite_without_claiming_a_remote_result(
    relay_runtime: tuple[RelayService, RelayStorage, FakeTransport],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, store, transport = relay_runtime
    await _prepare(service, store, monkeypatch)
    transport.failure = MCPToolContractDriftError("contract changed")

    with pytest.raises(RelayServiceError) as drift:
        await service.invoke(
            target_id="catalog",
            capability_token={"token_id": "cap-a"},
            arguments={"q": "invoice"},
            idempotency_key="drift-key",
            source_ip=None,
            reauthenticate=_context,
        )

    assert drift.value.code == "relay.schema_drift"
    assert drift.value.record is not None
    assert drift.value.record["status"] == "failed"
    assert drift.value.record["remote_result_observed"] is False
    assert drift.value.record["receipt"]["payload"]["remote_result_observed"] is False
    budget = store.get_budget(
        owner="owner-a", tenant_id="tenant-a", capability_token_id="cap-a"
    )
    assert budget["reserved_usd"] == 0
    assert budget["spent_usd"] == 0
