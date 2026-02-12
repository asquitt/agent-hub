from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import mean
from typing import Any

import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.gate import evaluate_gate

DEFAULT_PILOT_A = ROOT / "data" / "pilots" / "pilot_a_weekly.json"
DEFAULT_PILOT_B = ROOT / "data" / "pilots" / "pilot_b_weekly.json"
DEFAULT_JSON = ROOT / "docs" / "gate" / "S28_GATE_REVIEW.json"
DEFAULT_MD = ROOT / "docs" / "gate" / "S28_GATE_REVIEW.md"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def derive_metrics(pilot_a: dict[str, Any], pilot_b: dict[str, Any]) -> dict[str, Any]:
    a = pilot_a["metrics"]
    b = pilot_b["metrics"]

    reliability_success_rate = mean(
        [
            float(a["reliability"]["delegation_success_rate"]),
            float(b["reliability"]["delegation_success_rate"]),
        ]
    )
    pilot_workloads = int(a["reliability"]["total_delegations"]) + int(b["reliability"]["total_delegations"])
    avg_cost_variance = mean([float(a["cost"]["avg_relative_cost_variance"]), float(b["cost"]["avg_relative_cost_variance"])])
    avg_trust = mean([float(a["trust"]["avg_trust_score"]), float(b["trust"]["avg_trust_score"])])
    settled_contracts = int(a["marketplace"]["settled_contracts"]) + int(b["marketplace"]["settled_contracts"])
    total_contracts = int(a["marketplace"]["total_contracts"]) + int(b["marketplace"]["total_contracts"])

    partner_roi_ratio = round(1.0 + max(0.0, (avg_trust / 100.0) - avg_cost_variance), 6)
    contribution_margin_ratio = round((settled_contracts / total_contracts) if total_contracts > 0 else 0.0, 6)

    return {
        "reliability_success_rate": round(reliability_success_rate, 6),
        "pilot_workloads": pilot_workloads,
        "partner_roi_ratio": partner_roi_ratio,
        "partner_roi_sample_size": 2,
        "contribution_margin_ratio": contribution_margin_ratio,
        "multi_agent_tasks": pilot_workloads,
    }


def render_markdown(report: dict[str, Any], pilot_a: Path, pilot_b: Path) -> str:
    lines = [
        "# S28 Gate Review v2",
        "",
        f"- Decision: **{report['decision']}**",
        f"- Pilot inputs: `{pilot_a}` and `{pilot_b}`",
        "",
        "## Checks",
    ]
    for check in report["checks"]:
        status = "PASS" if check["passed"] else "FAIL"
        lines.append(f"- [{status}] {check['criterion']}")
    lines.append("")
    lines.append("## Blocking Reasons")
    if report["blocking_reasons"]:
        for reason in report["blocking_reasons"]:
            lines.append(f"- {reason}")
    else:
        lines.append("- None")
    lines.append("")
    lines.append("## Metrics Snapshot")
    for key, value in report["metrics_snapshot"].items():
        lines.append(f"- {key}: {value}")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate S28 gate review from pilot exports.")
    parser.add_argument("--pilot-a", type=Path, default=DEFAULT_PILOT_A)
    parser.add_argument("--pilot-b", type=Path, default=DEFAULT_PILOT_B)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_MD)
    args = parser.parse_args()

    pilot_a = _load(args.pilot_a)
    pilot_b = _load(args.pilot_b)
    metrics = derive_metrics(pilot_a, pilot_b)
    report = evaluate_gate(metrics)
    report["sources"] = {"pilot_a": str(args.pilot_a), "pilot_b": str(args.pilot_b)}

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.out_md.write_text(render_markdown(report, args.pilot_a, args.pilot_b), encoding="utf-8")

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
