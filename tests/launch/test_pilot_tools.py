from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_export_pilot_metrics_and_compare_scripts(tmp_path: Path) -> None:
    pilot_a = tmp_path / "pilot_a.json"
    pilot_b = tmp_path / "pilot_b.json"
    compare = tmp_path / "comparison.json"

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
            str(ROOT / "tools" / "pilots" / "compare_pilots.py"),
            "--pilot-a",
            str(pilot_a),
            "--pilot-b",
            str(pilot_b),
            "--output",
            str(compare),
        ],
        check=True,
    )

    a_payload = json.loads(pilot_a.read_text(encoding="utf-8"))
    b_payload = json.loads(pilot_b.read_text(encoding="utf-8"))
    comparison = json.loads(compare.read_text(encoding="utf-8"))

    assert a_payload["pilot_id"] == "pilot-a"
    assert b_payload["pilot_id"] == "pilot-b"
    assert "metrics" in a_payload and "reliability" in a_payload["metrics"]
    assert "connectors" in a_payload["metrics"]
    assert a_payload["metrics"]["connectors"]["configured_count"] >= 4
    assert a_payload["metrics"]["connectors"]["coverage_ratio"] >= 0.75
    assert "roi" in a_payload["metrics"]
    assert a_payload["metrics"]["roi"]["net_roi_usd"] > 0
    assert "complexity" in b_payload["metrics"]
    assert b_payload["metrics"]["complexity"]["avg_workflow_steps"] >= 5
    assert b_payload["metrics"]["cost"]["p95_relative_cost_variance"] >= 0
    assert "deltas" in comparison
    assert "net_roi_usd" in comparison["deltas"]
    assert "p95_relative_cost_variance" in comparison["deltas"]
