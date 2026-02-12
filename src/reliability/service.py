from __future__ import annotations

from dataclasses import asdict, dataclass
from math import ceil
from typing import Any

from src.delegation import storage as delegation_storage


@dataclass(frozen=True)
class SREPolicy:
    success_rate_slo: float = 0.99
    latency_p95_ms_slo: float = 3000.0
    min_samples_for_enforcement: int = 10
    error_budget_warning_ratio: float = 0.8
    half_open_error_rate_threshold: float = 0.15
    open_error_rate_threshold: float = 0.3
    open_hard_stop_rate_threshold: float = 0.2
    open_latency_multiplier: float = 1.5


DEFAULT_POLICY = SREPolicy()
DEFAULT_WINDOW_SIZE = 50


def _stage_latency_ms(row: dict[str, Any]) -> float | None:
    lifecycle = row.get("lifecycle")
    if not isinstance(lifecycle, list):
        return None
    for stage in lifecycle:
        if not isinstance(stage, dict):
            continue
        if stage.get("stage") != "delivery":
            continue
        details = stage.get("details")
        if not isinstance(details, dict):
            return None
        value = details.get("latency_ms")
        if isinstance(value, (int, float)):
            return float(value)
        return None
    return None


def _percentile(values: list[float], ratio: float) -> float:
    if not values:
        return 0.0
    sorted_values = sorted(values)
    idx = max(0, min(len(sorted_values) - 1, ceil(ratio * len(sorted_values)) - 1))
    return round(float(sorted_values[idx]), 3)


def _status_is_success(status: str) -> bool:
    return status == "completed"


def _status_is_hard_stop(status: str) -> bool:
    return status == "failed_hard_stop"


def _build_alerts(
    *,
    total: int,
    consumed_ratio: float,
    latency_p95_ms: float,
    hard_stop_rate: float,
    policy: SREPolicy,
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    if total < policy.min_samples_for_enforcement:
        return alerts

    if consumed_ratio >= 1.0:
        alerts.append(
            {
                "severity": "critical",
                "code": "error_budget.exhausted",
                "message": "Delegation error budget exhausted for evaluation window.",
            }
        )
    elif consumed_ratio >= policy.error_budget_warning_ratio:
        alerts.append(
            {
                "severity": "warning",
                "code": "error_budget.burn_rate_high",
                "message": "Delegation error budget burn rate is approaching exhaustion.",
            }
        )

    if latency_p95_ms > (policy.latency_p95_ms_slo * policy.open_latency_multiplier):
        alerts.append(
            {
                "severity": "critical",
                "code": "latency.slo_critical",
                "message": "Delegation p95 latency critically exceeds SLO.",
            }
        )
    elif latency_p95_ms > policy.latency_p95_ms_slo:
        alerts.append(
            {
                "severity": "warning",
                "code": "latency.slo_breach",
                "message": "Delegation p95 latency exceeds SLO.",
            }
        )

    if hard_stop_rate >= policy.open_hard_stop_rate_threshold:
        alerts.append(
            {
                "severity": "critical",
                "code": "circuit_breaker.hard_stop_rate",
                "message": "Hard-stop rate exceeded circuit-breaker governance threshold.",
            }
        )

    return alerts


def _circuit_breaker_state(
    *,
    total: int,
    error_rate: float,
    hard_stop_rate: float,
    consumed_ratio: float,
    latency_p95_ms: float,
    policy: SREPolicy,
) -> tuple[str, list[str]]:
    if total < policy.min_samples_for_enforcement:
        return "closed", ["insufficient_samples"]

    reasons: list[str] = []
    if error_rate >= policy.open_error_rate_threshold:
        reasons.append("error_rate_open_threshold")
    if hard_stop_rate >= policy.open_hard_stop_rate_threshold:
        reasons.append("hard_stop_rate_open_threshold")
    if latency_p95_ms > (policy.latency_p95_ms_slo * policy.open_latency_multiplier):
        reasons.append("latency_critical_threshold")
    if reasons:
        return "open", reasons

    half_open_reasons: list[str] = []
    if error_rate >= policy.half_open_error_rate_threshold:
        half_open_reasons.append("error_rate_half_open_threshold")
    if consumed_ratio >= policy.error_budget_warning_ratio:
        half_open_reasons.append("error_budget_warning_threshold")
    if latency_p95_ms > policy.latency_p95_ms_slo:
        half_open_reasons.append("latency_slo_breach")
    if half_open_reasons:
        return "half_open", half_open_reasons

    return "closed", ["within_governance_thresholds"]


def build_slo_dashboard(window_size: int = DEFAULT_WINDOW_SIZE, policy: SREPolicy = DEFAULT_POLICY) -> dict[str, Any]:
    rows = delegation_storage.load_records()
    window = rows[: max(1, int(window_size))]
    total = len(window)
    if total == 0:
        return {
            "policy": asdict(policy),
            "window": {"size": max(1, int(window_size)), "evaluated_delegations": 0},
            "metrics": {
                "success_rate": 1.0,
                "error_rate": 0.0,
                "hard_stop_rate": 0.0,
                "latency_p95_ms": 0.0,
            },
            "error_budget": {
                "allowed_errors": 1,
                "observed_errors": 0,
                "remaining_errors": 1,
                "consumed_ratio": 0.0,
            },
            "circuit_breaker": {
                "state": "closed",
                "governance_action": "allow",
                "reasons": ["no_delegation_history"],
            },
            "alerts": [],
        }

    success_count = 0
    error_count = 0
    hard_stop_count = 0
    latency_values: list[float] = []

    for row in window:
        status = str(row.get("status", "unknown"))
        if _status_is_success(status):
            success_count += 1
        else:
            error_count += 1
        if _status_is_hard_stop(status):
            hard_stop_count += 1

        latency_ms = _stage_latency_ms(row)
        if latency_ms is not None:
            latency_values.append(latency_ms)

    success_rate = round(success_count / total, 4)
    error_rate = round(error_count / total, 4)
    hard_stop_rate = round(hard_stop_count / total, 4)
    latency_p95_ms = _percentile(latency_values, 0.95)

    allowed_errors = max(1, int(total * (1.0 - policy.success_rate_slo)))
    remaining_errors = allowed_errors - error_count
    consumed_ratio = round(error_count / allowed_errors, 4)

    breaker_state, reasons = _circuit_breaker_state(
        total=total,
        error_rate=error_rate,
        hard_stop_rate=hard_stop_rate,
        consumed_ratio=consumed_ratio,
        latency_p95_ms=latency_p95_ms,
        policy=policy,
    )
    governance_action = "reject_new_delegations" if breaker_state == "open" else "allow"

    alerts = _build_alerts(
        total=total,
        consumed_ratio=consumed_ratio,
        latency_p95_ms=latency_p95_ms,
        hard_stop_rate=hard_stop_rate,
        policy=policy,
    )

    return {
        "policy": asdict(policy),
        "window": {"size": max(1, int(window_size)), "evaluated_delegations": total},
        "metrics": {
            "success_rate": success_rate,
            "error_rate": error_rate,
            "hard_stop_rate": hard_stop_rate,
            "latency_p95_ms": latency_p95_ms,
        },
        "error_budget": {
            "allowed_errors": allowed_errors,
            "observed_errors": error_count,
            "remaining_errors": remaining_errors,
            "consumed_ratio": consumed_ratio,
        },
        "circuit_breaker": {
            "state": breaker_state,
            "governance_action": governance_action,
            "reasons": reasons,
        },
        "alerts": alerts,
    }
