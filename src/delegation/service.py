from __future__ import annotations

import tempfile
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from src.delegation import storage
from src.trust.scoring import record_usage_event


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stage(name: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"stage": name, "timestamp": _utc_now(), "details": details or {}}


def _apply_budget_controls(estimated: float, actual: float, auto_reauthorize: bool) -> tuple[str, dict[str, Any]]:
    ratio = actual / max(estimated, 0.000001)
    controls = {
        "soft_alert": ratio >= 0.8,
        "reauthorization_required": ratio >= 1.0,
        "hard_stop": ratio >= 1.2,
        "ratio": round(ratio, 4),
    }

    if controls["hard_stop"]:
        return "hard_stop", controls
    if controls["reauthorization_required"] and not auto_reauthorize:
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
    actual_cost = float(simulated_actual_cost_usd if simulated_actual_cost_usd is not None else estimated_cost_usd * 0.92)

    lifecycle: list[dict[str, Any]] = []
    audit_trail: list[dict[str, Any]] = []

    lifecycle.append(_stage("discovery", {"requester": requester_agent_id, "delegate": delegate_agent_id}))
    lifecycle.append(_stage("negotiation", {"estimated_cost_usd": estimated_cost_usd, "max_budget_usd": max_budget_usd}))

    balances[requester_agent_id] = requester_balance - estimated_cost_usd
    storage.save_balances(balances)

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

    row = {
        "delegation_id": delegation_id,
        "requester_agent_id": requester_agent_id,
        "delegate_agent_id": delegate_agent_id,
        "task_spec": task_spec,
        "estimated_cost_usd": estimated_cost_usd,
        "actual_cost_usd": actual_cost,
        "max_budget_usd": max_budget_usd,
        "status": settlement_status,
        "policy_decision": policy_decision,
        "lifecycle": lifecycle,
        "audit_trail": audit_trail,
        "budget_controls": controls,
        "created_at": _utc_now(),
        "updated_at": _utc_now(),
    }

    storage.append_record(row)
    return row


def get_delegation_status(delegation_id: str) -> dict[str, Any] | None:
    row = storage.get_record(delegation_id)
    if not row:
        return None
    return {
        "delegation_id": row["delegation_id"],
        "status": row["status"],
        "requester_agent_id": row["requester_agent_id"],
        "delegate_agent_id": row["delegate_agent_id"],
        "estimated_cost_usd": row["estimated_cost_usd"],
        "actual_cost_usd": row["actual_cost_usd"],
        "budget_controls": row["budget_controls"],
        "policy_decision": row.get("policy_decision"),
        "lifecycle": row["lifecycle"],
        "audit_trail": row["audit_trail"],
    }
