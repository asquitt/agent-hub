from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_economics_hardening_tool_emits_threshold_status_and_recommendations(tmp_path: Path) -> None:
    pilot_a = tmp_path / "pilot_a.json"
    pilot_b = tmp_path / "pilot_b.json"
    report = tmp_path / "economics_hardening.json"

    subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "pilots" / "export_pilot_metrics.py"),
            "--pilot-id",
            "pilot-a",
            "--output",
            str(pilot_a),
        ],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "pilots" / "export_pilot_metrics.py"),
            "--pilot-id",
            "pilot-b",
            "--output",
            str(pilot_b),
        ],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "pilots" / "economics_hardening.py"),
            "--pilot-a",
            str(pilot_a),
            "--pilot-b",
            str(pilot_b),
            "--output",
            str(report),
        ],
        check=True,
    )

    payload = json.loads(report.read_text(encoding="utf-8"))
    snapshot = payload["economics_snapshot"]
    final = payload["optimization"]["final"]
    assert snapshot["multi_agent_tasks"] >= 100
    assert snapshot["contribution_margin_ratio"] >= 0.2
    assert snapshot["p95_cost_variance"] <= 0.15
    assert final["thresholds_met"] is True
