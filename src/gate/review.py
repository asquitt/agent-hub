from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class GateThresholds:
    reliability_success_rate_min: float = 0.99
    partner_roi_ratio_min: float = 1.05
    contribution_margin_ratio_min: float = 0.2
    minimum_multi_agent_tasks: int = 100


DEFAULT_THRESHOLDS = GateThresholds()


def _to_float(metrics: dict[str, Any], key: str) -> float:
    value = metrics.get(key)
    if value is None:
        return 0.0
    return float(value)


def _to_int(metrics: dict[str, Any], key: str) -> int:
    value = metrics.get(key)
    if value is None:
        return 0
    return int(value)


def evaluate_gate(metrics: dict[str, Any], thresholds: GateThresholds = DEFAULT_THRESHOLDS) -> dict[str, Any]:
    reliability_success_rate = _to_float(metrics, "reliability_success_rate")
    pilot_workloads = _to_int(metrics, "pilot_workloads")

    partner_roi_ratio = _to_float(metrics, "partner_roi_ratio")
    partner_roi_sample_size = _to_int(metrics, "partner_roi_sample_size")

    contribution_margin_ratio = _to_float(metrics, "contribution_margin_ratio")
    multi_agent_tasks = _to_int(metrics, "multi_agent_tasks")

    checks = [
        {
            "criterion": "Reliability target met in pilot workloads",
            "id": "reliability_target_met",
            "passed": reliability_success_rate >= thresholds.reliability_success_rate_min and pilot_workloads > 0,
            "observed": {
                "reliability_success_rate": reliability_success_rate,
                "pilot_workloads": pilot_workloads,
            },
            "threshold": {
                "reliability_success_rate_min": thresholds.reliability_success_rate_min,
                "pilot_workloads_min": 1,
            },
        },
        {
            "criterion": "Positive design-partner ROI evidence",
            "id": "positive_roi_evidence",
            "passed": partner_roi_ratio >= thresholds.partner_roi_ratio_min and partner_roi_sample_size > 0,
            "observed": {
                "partner_roi_ratio": partner_roi_ratio,
                "partner_roi_sample_size": partner_roi_sample_size,
            },
            "threshold": {
                "partner_roi_ratio_min": thresholds.partner_roi_ratio_min,
                "partner_roi_sample_size_min": 1,
            },
        },
        {
            "criterion": "Sustainable unit economics under real multi-agent load",
            "id": "sustainable_unit_economics",
            "passed": contribution_margin_ratio >= thresholds.contribution_margin_ratio_min
            and multi_agent_tasks >= thresholds.minimum_multi_agent_tasks,
            "observed": {
                "contribution_margin_ratio": contribution_margin_ratio,
                "multi_agent_tasks": multi_agent_tasks,
            },
            "threshold": {
                "contribution_margin_ratio_min": thresholds.contribution_margin_ratio_min,
                "multi_agent_tasks_min": thresholds.minimum_multi_agent_tasks,
            },
        },
    ]

    blocking_reasons = [check["criterion"] for check in checks if not check["passed"]]
    decision = "GO" if not blocking_reasons else "NO_GO"

    return {
        "decision": decision,
        "checks": checks,
        "blocking_reasons": blocking_reasons,
        "thresholds": asdict(thresholds),
        "metrics_snapshot": {
            "reliability_success_rate": reliability_success_rate,
            "pilot_workloads": pilot_workloads,
            "partner_roi_ratio": partner_roi_ratio,
            "partner_roi_sample_size": partner_roi_sample_size,
            "contribution_margin_ratio": contribution_margin_ratio,
            "multi_agent_tasks": multi_agent_tasks,
        },
    }
