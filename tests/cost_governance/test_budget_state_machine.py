from __future__ import annotations

from src.cost_governance.service import budget_state_from_ratio


def test_budget_state_machine_threshold_transitions() -> None:
    assert budget_state_from_ratio(0.79)["state"] == "ok"
    assert budget_state_from_ratio(0.80)["state"] == "soft_alert"
    assert budget_state_from_ratio(1.00, auto_reauthorize=False)["state"] == "reauthorization_required"
    assert budget_state_from_ratio(1.19, auto_reauthorize=False)["state"] == "reauthorization_required"
    assert budget_state_from_ratio(1.20)["state"] == "hard_stop"


def test_budget_state_machine_flags() -> None:
    state = budget_state_from_ratio(1.05, auto_reauthorize=True)
    assert state["soft_alert"] is True
    assert state["reauthorization_required"] is True
    assert state["hard_stop"] is False
