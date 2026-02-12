from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_pilot_b_expansion_reports_complexity_roi_and_cost_depth(tmp_path: Path) -> None:
    output = tmp_path / "pilot_b_expanded.json"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "pilots" / "export_pilot_metrics.py"),
            "--pilot-id",
            "pilot-b",
            "--output",
            str(output),
        ],
        check=True,
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    metrics = payload["metrics"]

    connectors = metrics["connectors"]
    assert connectors["configured_count"] >= 4
    assert connectors["active_count"] >= 4

    workloads = metrics["workloads"]
    assert workloads["planned_weekly_tasks"] >= 100
    assert len(workloads["profiles"]) >= 4

    complexity = metrics["complexity"]
    assert complexity["avg_workflow_steps"] >= 5
    assert complexity["avg_cross_system_hops"] >= 3
    assert complexity["high_risk_workload_ratio"] >= 0.25

    reliability = metrics["reliability"]
    assert reliability["complexity_adjusted_success_rate"] <= reliability["delegation_success_rate"]
    assert reliability["planned_workload_tasks"] == workloads["planned_weekly_tasks"]

    cost = metrics["cost"]
    assert cost["p95_relative_cost_variance"] >= cost["avg_relative_cost_variance"]
    assert cost["cost_per_planned_task_usd"] > 0

    roi = metrics["roi"]
    assert roi["net_roi_usd"] > 0
    assert roi["roi_ratio"] > 0
    assert roi["margin_proxy_ratio"] > 0
