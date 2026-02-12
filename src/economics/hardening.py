from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class EconomicsThresholds:
    contribution_margin_ratio_min: float = 0.20
    variance_p95_max: float = 0.15
    minimum_multi_agent_tasks: int = 100


DEFAULT_THRESHOLDS = EconomicsThresholds()


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def aggregate_pilot_economics(metrics: list[dict[str, Any]]) -> dict[str, Any]:
    if not metrics:
        return {
            "pilot_count": 0,
            "contribution_margin_ratio": 0.0,
            "avg_roi_ratio": 0.0,
            "p95_cost_variance": 0.0,
            "multi_agent_tasks": 0,
        }

    margins: list[float] = []
    roi_ratios: list[float] = []
    variances: list[float] = []
    multi_agent_tasks = 0
    for row in metrics:
        roi = row.get("roi", {}) if isinstance(row.get("roi"), dict) else {}
        cost = row.get("cost", {}) if isinstance(row.get("cost"), dict) else {}
        workloads = row.get("workloads", {}) if isinstance(row.get("workloads"), dict) else {}
        reliability = row.get("reliability", {}) if isinstance(row.get("reliability"), dict) else {}

        margin = _to_float(roi.get("margin_proxy_ratio"), default=None) if roi else None
        if margin is None:
            labor_savings = _to_float(roi.get("estimated_labor_savings_usd"), default=0.0)
            net_roi = _to_float(roi.get("net_roi_usd"), default=0.0)
            margin = net_roi / max(labor_savings, 1e-6)
        margins.append(max(0.0, margin))

        roi_ratios.append(_to_float(roi.get("roi_ratio"), default=0.0))
        variances.append(_to_float(cost.get("p95_relative_cost_variance"), default=_to_float(cost.get("avg_relative_cost_variance"), 0.0)))
        multi_agent_tasks += _to_int(workloads.get("planned_weekly_tasks"), default=_to_int(reliability.get("total_delegations"), 0))

    pilot_count = len(metrics)
    return {
        "pilot_count": pilot_count,
        "contribution_margin_ratio": round(sum(margins) / pilot_count, 6),
        "avg_roi_ratio": round(sum(roi_ratios) / pilot_count, 6),
        "p95_cost_variance": round(sum(variances) / pilot_count, 6),
        "multi_agent_tasks": int(multi_agent_tasks),
    }


def evaluate_economics_thresholds(
    snapshot: dict[str, Any],
    thresholds: EconomicsThresholds = DEFAULT_THRESHOLDS,
) -> dict[str, Any]:
    margin = _to_float(snapshot.get("contribution_margin_ratio"), 0.0)
    variance = _to_float(snapshot.get("p95_cost_variance"), 0.0)
    tasks = _to_int(snapshot.get("multi_agent_tasks"), 0)
    margin_pass = margin >= thresholds.contribution_margin_ratio_min
    variance_pass = variance <= thresholds.variance_p95_max
    tasks_pass = tasks >= thresholds.minimum_multi_agent_tasks
    return {
        "margin_pass": margin_pass,
        "variance_pass": variance_pass,
        "tasks_pass": tasks_pass,
        "thresholds_met": margin_pass and variance_pass and tasks_pass,
    }


def optimize_economics(
    snapshot: dict[str, Any],
    thresholds: EconomicsThresholds = DEFAULT_THRESHOLDS,
    *,
    max_iterations: int = 12,
) -> dict[str, Any]:
    current = {
        "contribution_margin_ratio": _to_float(snapshot.get("contribution_margin_ratio"), 0.0),
        "p95_cost_variance": _to_float(snapshot.get("p95_cost_variance"), 0.0),
        "multi_agent_tasks": _to_int(snapshot.get("multi_agent_tasks"), 0),
    }
    iterations: list[dict[str, Any]] = []
    recommendations: list[str] = []

    for index in range(1, max_iterations + 1):
        gates = evaluate_economics_thresholds(current, thresholds)
        if gates["thresholds_met"]:
            break
        actions: list[dict[str, Any]] = []
        if not gates["margin_pass"]:
            gap = max(0.0, thresholds.contribution_margin_ratio_min - current["contribution_margin_ratio"])
            reduction_pct = min(0.20, max(0.03, gap * 0.5))
            current["contribution_margin_ratio"] = min(
                0.98,
                current["contribution_margin_ratio"] + reduction_pct * (1.0 - current["contribution_margin_ratio"]),
            )
            actions.append(
                {
                    "lever": "reduce_platform_cost_per_task",
                    "delta_pct": round(reduction_pct, 6),
                }
            )
        if not gates["variance_pass"]:
            overage = max(0.0, current["p95_cost_variance"] - thresholds.variance_p95_max)
            improvement_pct = min(0.25, max(0.05, overage * 0.6))
            current["p95_cost_variance"] = max(0.0, current["p95_cost_variance"] * (1.0 - improvement_pct))
            actions.append(
                {
                    "lever": "tighten_cost_guardrails_and_batching",
                    "delta_pct": round(improvement_pct, 6),
                }
            )
        if not gates["tasks_pass"]:
            recommendations.append("Increase representative multi-agent workload volume to satisfy gate minimum.")
        iterations.append(
            {
                "iteration": index,
                "actions": actions,
                "projected": {
                    "contribution_margin_ratio": round(current["contribution_margin_ratio"], 6),
                    "p95_cost_variance": round(current["p95_cost_variance"], 6),
                    "multi_agent_tasks": int(current["multi_agent_tasks"]),
                },
            }
        )

    final_gates = evaluate_economics_thresholds(current, thresholds)
    if not final_gates["tasks_pass"]:
        recommendations.append("Run additional pilot tasks to reach minimum multi-agent load requirement.")
    return {
        "initial": {
            "contribution_margin_ratio": round(_to_float(snapshot.get("contribution_margin_ratio"), 0.0), 6),
            "p95_cost_variance": round(_to_float(snapshot.get("p95_cost_variance"), 0.0), 6),
            "multi_agent_tasks": _to_int(snapshot.get("multi_agent_tasks"), 0),
        },
        "iterations": iterations,
        "final": {
            "contribution_margin_ratio": round(current["contribution_margin_ratio"], 6),
            "p95_cost_variance": round(current["p95_cost_variance"], 6),
            "multi_agent_tasks": int(current["multi_agent_tasks"]),
            **final_gates,
        },
        "thresholds": asdict(thresholds),
        "recommendations": recommendations,
    }
