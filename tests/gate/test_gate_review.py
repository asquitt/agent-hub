from __future__ import annotations

from src.gate import evaluate_gate


def test_gate_review_go_decision_when_all_criteria_pass() -> None:
    report = evaluate_gate(
        {
            "reliability_success_rate": 0.997,
            "pilot_workloads": 120,
            "partner_roi_ratio": 1.4,
            "partner_roi_sample_size": 3,
            "contribution_margin_ratio": 0.35,
            "multi_agent_tasks": 250,
        }
    )

    assert report["decision"] == "GO"
    assert report["blocking_reasons"] == []
    assert all(check["passed"] for check in report["checks"])


def test_gate_review_no_go_when_unit_economics_or_reliability_fails() -> None:
    report = evaluate_gate(
        {
            "reliability_success_rate": 0.92,
            "pilot_workloads": 80,
            "partner_roi_ratio": 1.2,
            "partner_roi_sample_size": 2,
            "contribution_margin_ratio": 0.05,
            "multi_agent_tasks": 70,
        }
    )

    assert report["decision"] == "NO_GO"
    assert "Reliability target met in pilot workloads" in report["blocking_reasons"]
    assert "Sustainable unit economics under real multi-agent load" in report["blocking_reasons"]
