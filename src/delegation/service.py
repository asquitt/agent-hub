from __future__ import annotations

import tempfile
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from src.cost_governance.service import budget_state_from_ratio, record_metering_event
from src.delegation import storage
from src.trust.scoring import record_usage_event

DELEGATION_CONTRACT_V2 = {
    "version": "delegation-contract-v2",
    "idempotency_required": True,
    "sla": {
        "p95_latency_ms_target": 3000,
        "max_end_to_end_timeout_ms": 8000,
    },
    "timeouts_ms": {
        "discovery": 500,
        "negotiation": 800,
        "execution": 5000,
        "delivery": 800,
        "settlement": 900,
    },
    "retry_matrix": {
        "transient_network_error": {"max_retries": 2, "backoff_ms": [100, 250], "idempotency_required": True},
        "delegate_timeout": {"max_retries": 1, "backoff_ms": [200], "idempotency_required": True},
        "policy_denied": {"max_retries": 0, "backoff_ms": [], "idempotency_required": True},
        "hard_stop_budget": {"max_retries": 0, "backoff_ms": [], "idempotency_required": True},
    },
    "circuit_breakers": {
        "soft_alert_pct": 80,
        "reauthorization_pct": 100,
        "hard_stop_pct": 120,
    },
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stage(name: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"stage": name, "timestamp": _utc_now(), "details": details or {}}


def _apply_budget_controls(estimated: float, actual: float, auto_reauthorize: bool) -> tuple[str, dict[str, Any]]:
    ratio = actual / max(estimated, 0.000001)
    controls = budget_state_from_ratio(ratio=ratio, auto_reauthorize=auto_reauthorize)

    if controls["hard_stop"]:
        return "hard_stop", controls
    if controls["state"] == "reauthorization_required":
        return "needs_reauthorization", controls
    return "ok", controls


def create_delegation(
    requester_agent_id: str,
    delegate_agent_id: str,
    task_spec: str,
    estimated_cost_usd: float,
    max_budget_usd: float,
    simulated_actual_cost_usd: float | None = None,
    auto_reauthorize: bool = True,
    policy_decision: dict[str, Any] | None = None,
    metering_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if estimated_cost_usd > max_budget_usd:
        raise ValueError("hard ceiling exceeded: estimated cost above max budget")

    balances = storage.load_balances()
    requester_balance = balances.get(requester_agent_id, 1000.0)
    if requester_balance < estimated_cost_usd:
        raise ValueError("insufficient requester balance for escrow")

    delegation_id = str(uuid.uuid4())
    storage.upsert_queue_state(delegation_id=delegation_id, status="queued", increment_attempt=True)
    actual_cost = float(simulated_actual_cost_usd if simulated_actual_cost_usd is not None else estimated_cost_usd * 0.92)

    lifecycle: list[dict[str, Any]] = []
    audit_trail: list[dict[str, Any]] = []

    try:
        lifecycle.append(_stage("discovery", {"requester": requester_agent_id, "delegate": delegate_agent_id}))
        lifecycle.append(_stage("negotiation", {"estimated_cost_usd": estimated_cost_usd, "max_budget_usd": max_budget_usd}))

        balances[requester_agent_id] = requester_balance - estimated_cost_usd
        storage.save_balances(balances)

        storage.upsert_queue_state(delegation_id=delegation_id, status="running")
        with tempfile.TemporaryDirectory(prefix="agenthub-delegation-sandbox-") as sandbox:
            start = time.perf_counter()
            lifecycle.append(_stage("execution", {"sandbox_path": sandbox, "network": "disabled", "status": "started"}))

            default_metering = [
                {"event": "llm_call", "tokens": 350, "cost_usd": round(actual_cost * 0.4, 6)},
                {"event": "tool_call", "tool": "delegate_tool", "cost_usd": round(actual_cost * 0.6, 6)},
            ]
            for row in (metering_events or default_metering):
                audit_trail.append(
                    {
                        "timestamp": _utc_now(),
                        "delegation_id": delegation_id,
                        "type": row.get("event", "metering"),
                        "details": row,
                    }
                )

            latency_ms = round((time.perf_counter() - start) * 1000, 3)

        lifecycle.append(_stage("delivery", {"output_schema_valid": True, "latency_ms": latency_ms}))

        budget_status, controls = _apply_budget_controls(estimated_cost_usd, actual_cost, auto_reauthorize)

        settlement_status = "completed"
        if budget_status == "hard_stop":
            settlement_status = "failed_hard_stop"
        elif budget_status == "needs_reauthorization":
            settlement_status = "pending_reauthorization"

        release_amount = max(0.0, estimated_cost_usd - actual_cost)
        balances = storage.load_balances()
        balances[requester_agent_id] = balances.get(requester_agent_id, 0.0) + release_amount
        storage.save_balances(balances)

        lifecycle.append(
            _stage(
                "settlement",
                {
                    "settlement_status": settlement_status,
                    "estimated_cost_usd": estimated_cost_usd,
                    "actual_cost_usd": actual_cost,
                    "escrow_refund_usd": round(release_amount, 6),
                    "budget_controls": controls,
                },
            )
        )

        delegation_success = settlement_status == "completed"
        lifecycle.append(_stage("feedback", {"success": delegation_success, "quality_score": 1.0 if delegation_success else 0.0}))

        record_usage_event(agent_id=delegate_agent_id, success=delegation_success, cost_usd=actual_cost, latency_ms=latency_ms)
        record_metering_event(
            actor=requester_agent_id,
            operation="delegation.create",
            cost_usd=actual_cost,
            metadata={
                "delegation_id": delegation_id,
                "delegate_agent_id": delegate_agent_id,
                "budget_ratio": controls["ratio"],
                "budget_state": controls["state"],
            },
        )

        storage.upsert_queue_state(delegation_id=delegation_id, status=settlement_status)
        queue_state = storage.get_queue_state(delegation_id)
        row = {
            "delegation_id": delegation_id,
            "requester_agent_id": requester_agent_id,
            "delegate_agent_id": delegate_agent_id,
            "task_spec": task_spec,
            "estimated_cost_usd": estimated_cost_usd,
            "actual_cost_usd": actual_cost,
            "max_budget_usd": max_budget_usd,
            "status": settlement_status,
            "contract": DELEGATION_CONTRACT_V2,
            "policy_decision": policy_decision,
            "lifecycle": lifecycle,
            "audit_trail": audit_trail,
            "budget_controls": controls,
            "queue_state": queue_state,
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
        }

        storage.append_record(row)
        return row
    except Exception as exc:
        storage.upsert_queue_state(delegation_id=delegation_id, status="failed", last_error=str(exc))
        raise


def get_delegation_status(delegation_id: str) -> dict[str, Any] | None:
    row = storage.get_record(delegation_id)
    if not row:
        return None
    queue_state = storage.get_queue_state(delegation_id) or row.get("queue_state")
    return {
        "delegation_id": row["delegation_id"],
        "status": row["status"],
        "contract": row.get("contract", DELEGATION_CONTRACT_V2),
        "requester_agent_id": row["requester_agent_id"],
        "delegate_agent_id": row["delegate_agent_id"],
        "estimated_cost_usd": row["estimated_cost_usd"],
        "actual_cost_usd": row["actual_cost_usd"],
        "budget_controls": row["budget_controls"],
        "policy_decision": row.get("policy_decision"),
        "lifecycle": row["lifecycle"],
        "audit_trail": row["audit_trail"],
        "queue_state": queue_state,
    }


def delegation_contract() -> dict[str, Any]:
    return DELEGATION_CONTRACT_V2
