from __future__ import annotations

from typing import Any

from src.common.time import utc_now_iso
from src.cost_governance import storage


def budget_state_from_ratio(ratio: float, auto_reauthorize: bool = True) -> dict[str, Any]:
    soft_alert = ratio >= 0.8
    needs_reauthorization = ratio >= 1.0 and not auto_reauthorize
    hard_stop = ratio >= 1.2
    if hard_stop:
        state = "hard_stop"
    elif needs_reauthorization:
        state = "reauthorization_required"
    elif soft_alert:
        state = "soft_alert"
    else:
        state = "ok"

    return {
        "state": state,
        "soft_alert": soft_alert,
        "reauthorization_required": ratio >= 1.0,
        "hard_stop": hard_stop,
        "ratio": round(ratio, 4),
    }


def record_metering_event(
    *,
    actor: str,
    operation: str,
    cost_usd: float,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row = {
        "timestamp": utc_now_iso(),
        "actor": actor,
        "operation": operation,
        "cost_usd": round(float(cost_usd), 6),
        "metadata": metadata or {},
    }
    storage.append_event(row)
    return row


def list_metering_events(limit: int = 100) -> list[dict[str, Any]]:
    rows = storage.load_events()
    rows.sort(key=lambda row: row.get("timestamp", ""), reverse=True)
    return rows[:limit]
