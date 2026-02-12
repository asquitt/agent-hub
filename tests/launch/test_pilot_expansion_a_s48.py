from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_pilot_a_expansion_reports_connector_depth_and_roi(tmp_path: Path) -> None:
    output = tmp_path / "pilot_a_expanded.json"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "pilots" / "export_pilot_metrics.py"),
            "--pilot-id",
            "pilot-a",
            "--output",
            str(output),
        ],
        check=True,
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    metrics = payload["metrics"]

    connectors = metrics["connectors"]
    assert connectors["configured_count"] >= 5
    assert connectors["active_count"] >= 4
    assert connectors["coverage_ratio"] >= 0.8

    workloads = metrics["workloads"]
    assert workloads["planned_weekly_tasks"] >= 120
    assert len(workloads["profiles"]) >= 5

    roi = metrics["roi"]
    assert roi["estimated_hours_saved"] > 0
    assert roi["estimated_labor_savings_usd"] > roi["estimated_platform_spend_usd"]
    assert roi["net_roi_usd"] > 0
    assert roi["roi_ratio"] > 0

    reliability = metrics["reliability"]
    assert reliability["planned_workload_tasks"] == workloads["planned_weekly_tasks"]
