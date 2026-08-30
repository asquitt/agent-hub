from __future__ import annotations

import pytest

from src.relay.storage import RelayBudgetError, RelayConflictError, RelayStorage


def _target() -> dict:
    return {
        "target_id": "catalog",
        "tenant_id": "tenant-a",
        "endpoint_url": "https://mcp.example/mcp",
        "endpoint_digest": "endpoint-digest",
        "tool_name": "lookup",
        "server_name": "catalog-server",
        "server_version": "1.0.0",
        "protocol_version": "2025-11-25",
        "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}},
        "output_schema": {
            "type": "object",
            "properties": {"answer": {"type": "string"}},
        },
        "schema_digest": "schema-digest",
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        "operator_attests_read_only": True,
        "max_call_cost_usd": 1.0,
        "policy_revision": "policy-revision",
    }


def _reserve(
    store: RelayStorage, key: str = "key-1", request_hash: str = "request-1"
) -> dict:
    row, created = store.reserve_invocation(
        owner="owner-a",
        tenant_id="tenant-a",
        agent_id="agent-a",
        idempotency_key=key,
        request_hash=request_hash,
        target_id="catalog",
        capability_token_id="cap-a",
        input_hash="input-hash",
    )
    assert created is True
    return row


def test_relay_storage_persists_target_and_domain_idempotency(tmp_path) -> None:
    path = tmp_path / "relay.db"
    store = RelayStorage()
    store.reset_for_tests(path)
    saved = store.upsert_target(_target())
    assert saved["schema_digest"] == "schema-digest"

    first = _reserve(store)
    replay, created = store.reserve_invocation(
        owner="owner-a",
        tenant_id="tenant-a",
        agent_id="agent-a",
        idempotency_key="key-1",
        request_hash="request-1",
        target_id="catalog",
        capability_token_id="cap-a",
        input_hash="input-hash",
    )
    assert created is False
    assert replay["invocation_id"] == first["invocation_id"]
    with pytest.raises(RelayConflictError):
        store.reserve_invocation(
            owner="owner-a",
            tenant_id="tenant-a",
            agent_id="agent-a",
            idempotency_key="key-1",
            request_hash="different",
            target_id="catalog",
            capability_token_id="cap-a",
            input_hash="different",
        )

    store.close()
    reloaded = RelayStorage()
    reloaded.reconfigure(path)
    assert reloaded.get_target("catalog")["input_schema"]["type"] == "object"
    assert (
        reloaded.get_invocation_unscoped(first["invocation_id"])["status"] == "pending"
    )


def test_budget_reservation_is_atomic_and_charged_once(tmp_path) -> None:
    store = RelayStorage()
    store.reset_for_tests(tmp_path / "relay.db")
    store.upsert_target(_target())
    store.set_budget(
        owner="owner-a",
        tenant_id="tenant-a",
        capability_token_id="cap-a",
        max_budget_usd=10.0,
    )
    invocation = _reserve(store)
    budget = store.reserve_budget(
        invocation_id=invocation["invocation_id"],
        policy={"allowed": True},
        cost_usd=1.0,
    )
    assert budget["state"] == "ok"
    store.mark_network_started(
        invocation["invocation_id"], target_snapshot=store.get_target("catalog")
    )
    finalized = store.finalize(
        invocation_id=invocation["invocation_id"],
        status="succeeded",
        output_hash="output-hash",
        result={"answer": "ok"},
        error_code=None,
        error_message=None,
        receipt={"signature": "test"},
        remote_result_observed=True,
        charge_reserved=True,
    )
    assert finalized["charged_cost_usd"] == 1.0
    account = store.get_budget(
        owner="owner-a", tenant_id="tenant-a", capability_token_id="cap-a"
    )
    assert account["spent_usd"] == 1.0
    assert account["reserved_usd"] == 0.0


def test_budget_reauthorization_fails_before_network_and_releases_nothing(
    tmp_path,
) -> None:
    store = RelayStorage()
    store.reset_for_tests(tmp_path / "relay.db")
    store.upsert_target(_target())
    store.set_budget(
        owner="owner-a",
        tenant_id="tenant-a",
        capability_token_id="cap-a",
        max_budget_usd=1.0,
    )
    invocation = _reserve(store)
    with pytest.raises(RelayBudgetError) as exc_info:
        store.reserve_budget(
            invocation_id=invocation["invocation_id"],
            policy={"allowed": True},
            cost_usd=1.0,
        )
    assert exc_info.value.code == "budget.reauthorization_required"
    failed = store.fail_before_dispatch(
        invocation_id=invocation["invocation_id"],
        error_code=exc_info.value.code,
        error_message=str(exc_info.value),
        budget=exc_info.value.budget,
    )
    assert failed["status"] == "failed"
    assert failed["network_started_at"] is None


@pytest.mark.parametrize("maximum", [float("inf"), float("-inf"), float("nan")])
def test_budget_storage_rejects_non_finite_limits(tmp_path, maximum: float) -> None:
    store = RelayStorage()
    store.reset_for_tests(tmp_path / "relay.db")
    with pytest.raises(ValueError, match="finite and greater than zero"):
        store.set_budget(
            owner="owner-a",
            tenant_id="tenant-a",
            capability_token_id="cap-a",
            max_budget_usd=maximum,
        )


@pytest.mark.parametrize(
    ("cost_usd", "expected_state", "expected_code"),
    [
        (0.8, "soft_alert", None),
        (1.2, "hard_stop", "budget.hard_stop"),
    ],
)
def test_budget_threshold_contract(
    tmp_path, cost_usd: float, expected_state: str, expected_code: str | None
) -> None:
    store = RelayStorage()
    store.reset_for_tests(tmp_path / f"relay-{expected_state}.db")
    store.upsert_target(_target())
    store.set_budget(
        owner="owner-a",
        tenant_id="tenant-a",
        capability_token_id="cap-a",
        max_budget_usd=1.0,
    )
    invocation = _reserve(store)
    if expected_code is None:
        budget = store.reserve_budget(
            invocation_id=invocation["invocation_id"],
            policy={"allowed": True},
            cost_usd=cost_usd,
        )
        assert budget["state"] == expected_state
        return

    with pytest.raises(RelayBudgetError) as exc_info:
        store.reserve_budget(
            invocation_id=invocation["invocation_id"],
            policy={"allowed": True},
            cost_usd=cost_usd,
        )
    assert exc_info.value.code == expected_code
    assert exc_info.value.budget["state"] == expected_state


def test_recovery_never_replays_and_charges_only_dispatched_calls(tmp_path) -> None:
    store = RelayStorage()
    store.reset_for_tests(tmp_path / "relay.db")
    store.upsert_target(_target())
    store.set_budget(
        owner="owner-a",
        tenant_id="tenant-a",
        capability_token_id="cap-a",
        max_budget_usd=10.0,
    )
    before = _reserve(store, key="before")
    after = _reserve(store, key="after", request_hash="request-2")
    for invocation in (before, after):
        store.reserve_budget(
            invocation_id=invocation["invocation_id"],
            policy={"allowed": True},
            cost_usd=1.0,
        )
    store.mark_network_started(
        after["invocation_id"], target_snapshot=store.get_target("catalog")
    )

    recovered = store.recover_abandoned()
    assert {row["status"] for row in recovered} == {"failed", "indeterminate"}
    assert store.get_invocation_unscoped(before["invocation_id"])["status"] == "failed"
    assert (
        store.get_invocation_unscoped(after["invocation_id"])["status"]
        == "indeterminate"
    )
    account = store.get_budget(
        owner="owner-a", tenant_id="tenant-a", capability_token_id="cap-a"
    )
    assert account["spent_usd"] == 1.0
    assert account["reserved_usd"] == 0.0
