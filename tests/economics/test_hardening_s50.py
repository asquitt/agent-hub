from __future__ import annotations

from src.economics import aggregate_pilot_economics, evaluate_economics_thresholds, optimize_economics


def _pilot_metric(margin: float, roi_ratio: float, variance: float, tasks: int) -> dict:
    labor = 1000.0
    net_roi = labor * margin
    return {
        "roi": {
            "margin_proxy_ratio": margin,
            "roi_ratio": roi_ratio,
            "estimated_labor_savings_usd": labor,
            "net_roi_usd": net_roi,
        },
        "cost": {"p95_relative_cost_variance": variance, "avg_relative_cost_variance": variance},
        "workloads": {"planned_weekly_tasks": tasks},
        "reliability": {"total_delegations": tasks},
    }


def test_aggregate_pilot_economics_computes_margin_variance_and_task_volume() -> None:
    snapshot = aggregate_pilot_economics(
        [
            _pilot_metric(margin=0.32, roi_ratio=2.0, variance=0.12, tasks=80),
            _pilot_metric(margin=0.28, roi_ratio=1.7, variance=0.14, tasks=90),
        ]
    )
    assert snapshot["pilot_count"] == 2
    assert snapshot["contribution_margin_ratio"] == 0.3
    assert snapshot["avg_roi_ratio"] == 1.85
    assert snapshot["p95_cost_variance"] == 0.13
    assert snapshot["multi_agent_tasks"] == 170


def test_optimize_economics_closes_margin_and_variance_gaps() -> None:
    snapshot = {
        "contribution_margin_ratio": 0.07,
        "p95_cost_variance": 0.28,
        "multi_agent_tasks": 160,
    }
    result = optimize_economics(snapshot)
    assert result["final"]["thresholds_met"] is True
    assert result["final"]["contribution_margin_ratio"] >= 0.2
    assert result["final"]["p95_cost_variance"] <= 0.15
    assert len(result["iterations"]) >= 1


def test_optimize_economics_surfaces_volume_recommendation_when_task_floor_missing() -> None:
    snapshot = {
        "contribution_margin_ratio": 0.34,
        "p95_cost_variance": 0.1,
        "multi_agent_tasks": 20,
    }
    result = optimize_economics(snapshot)
    assert result["final"]["thresholds_met"] is False
    assert result["final"]["tasks_pass"] is False
    assert any("multi-agent load" in message for message in result["recommendations"])
    gates = evaluate_economics_thresholds(snapshot)
    assert gates["margin_pass"] is True
    assert gates["variance_pass"] is True
