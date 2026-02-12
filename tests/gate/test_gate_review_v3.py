from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.gate.review_v3 import build_review


def _pilot_payload(pilot_id: str) -> dict:
    return {
        "pilot_id": pilot_id,
        "metrics": {
            "reliability": {
                "delegation_success_rate": 0.995,
                "complexity_adjusted_success_rate": 0.995,
                "total_delegations": 40,
                "completed_delegations": 39,
                "hard_stop_count": 0,
            },
            "workloads": {"planned_weekly_tasks": 130},
            "cost": {"avg_relative_cost_variance": 0.1, "p95_relative_cost_variance": 0.12},
            "trust": {"avg_trust_score": 70.0, "unresolved_incidents": 0},
            "roi": {"roi_ratio": 1.5, "margin_proxy_ratio": 0.35},
            "marketplace": {"settled_contracts": 5, "total_contracts": 10},
        },
    }


def _economics_payload(thresholds_met: bool) -> dict:
    return {
        "economics_snapshot": {
            "pilot_count": 2,
            "contribution_margin_ratio": 0.35,
            "avg_roi_ratio": 1.5,
            "p95_cost_variance": 0.12,
            "multi_agent_tasks": 260,
        },
        "optimization": {
            "final": {
                "contribution_margin_ratio": 0.35,
                "p95_cost_variance": 0.12,
                "multi_agent_tasks": 260,
                "margin_pass": True,
                "variance_pass": True,
                "tasks_pass": True,
                "thresholds_met": thresholds_met,
            }
        },
    }


def test_gate_review_v3_script_generates_gate_package(tmp_path: Path) -> None:
    pilot_a = tmp_path / "pilot_a.json"
    pilot_b = tmp_path / "pilot_b.json"
    economics = tmp_path / "economics.json"
    out_json = tmp_path / "s51.json"
    out_md = tmp_path / "s51.md"

    pilot_a.write_text(json.dumps(_pilot_payload("pilot-a")), encoding="utf-8")
    pilot_b.write_text(json.dumps(_pilot_payload("pilot-b")), encoding="utf-8")
    economics.write_text(json.dumps(_economics_payload(thresholds_met=True)), encoding="utf-8")

    subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "gate" / "review_v3.py"),
            "--pilot-a",
            str(pilot_a),
            "--pilot-b",
            str(pilot_b),
            "--economics",
            str(economics),
            "--out-json",
            str(out_json),
            "--out-md",
            str(out_md),
        ],
        check=True,
    )

    report = json.loads(out_json.read_text(encoding="utf-8"))
    assert report["gate_version"] == "v3"
    assert report["decision"] == "GO"
    assert report["independent_evidence"]["economics_thresholds_met"] is True
    assert "pilot_a_sha256" in report["source_hashes"]
    assert out_md.exists()


def test_gate_review_v3_forces_no_go_when_economics_thresholds_fail(tmp_path: Path) -> None:
    pilot_a = tmp_path / "pilot_a.json"
    pilot_b = tmp_path / "pilot_b.json"
    economics = tmp_path / "economics.json"

    pilot_a.write_text(json.dumps(_pilot_payload("pilot-a")), encoding="utf-8")
    pilot_b.write_text(json.dumps(_pilot_payload("pilot-b")), encoding="utf-8")
    economics.write_text(json.dumps(_economics_payload(thresholds_met=False)), encoding="utf-8")

    report = build_review(pilot_a_path=pilot_a, pilot_b_path=pilot_b, economics_path=economics)
    assert report["decision"] == "NO_GO"
    assert any("Economics hardening thresholds not met" in reason for reason in report["blocking_reasons"])
