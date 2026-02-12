from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_gate_review_v2_script_generates_outputs(tmp_path: Path) -> None:
    pilot_a = tmp_path / "pilot_a.json"
    pilot_b = tmp_path / "pilot_b.json"
    out_json = tmp_path / "s28.json"
    out_md = tmp_path / "s28.md"

    pilot_payload = {
        "pilot_id": "pilot-a",
        "metrics": {
            "reliability": {"delegation_success_rate": 1.0, "total_delegations": 10, "completed_delegations": 10, "hard_stop_count": 0},
            "cost": {"avg_relative_cost_variance": 0.1, "metering_events": 20},
            "trust": {"avg_trust_score": 70.0, "unresolved_incidents": 0},
            "marketplace": {"settled_contracts": 5, "total_contracts": 10},
        },
    }
    pilot_a.write_text(json.dumps(pilot_payload), encoding="utf-8")
    pilot_payload["pilot_id"] = "pilot-b"
    pilot_b.write_text(json.dumps(pilot_payload), encoding="utf-8")

    subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "gate" / "review_v2.py"),
            "--pilot-a",
            str(pilot_a),
            "--pilot-b",
            str(pilot_b),
            "--out-json",
            str(out_json),
            "--out-md",
            str(out_md),
        ],
        check=True,
    )

    report = json.loads(out_json.read_text(encoding="utf-8"))
    assert report["decision"] in {"GO", "NO_GO"}
    assert "checks" in report
    assert out_md.exists()
