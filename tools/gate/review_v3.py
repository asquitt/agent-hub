from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.gate import evaluate_gate
from tools.gate.review_v2 import derive_metrics

DEFAULT_PILOT_A = ROOT / "data" / "pilots" / "pilot_a_weekly.json"
DEFAULT_PILOT_B = ROOT / "data" / "pilots" / "pilot_b_weekly.json"
DEFAULT_ECONOMICS = ROOT / "data" / "pilots" / "economics_hardening.json"
DEFAULT_JSON = ROOT / "docs" / "gate" / "S51_GATE_REVIEW.json"
DEFAULT_MD = ROOT / "docs" / "gate" / "S51_GATE_REVIEW.md"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_review(
    *,
    pilot_a_path: Path,
    pilot_b_path: Path,
    economics_path: Path,
) -> dict[str, Any]:
    pilot_a = _load(pilot_a_path)
    pilot_b = _load(pilot_b_path)
    economics = _load(economics_path)

    metrics = derive_metrics(pilot_a, pilot_b)
    report = evaluate_gate(metrics)
    report["gate_version"] = "v3"
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    report["sources"] = {
        "pilot_a": str(pilot_a_path),
        "pilot_b": str(pilot_b_path),
        "economics": str(economics_path),
    }
    report["source_hashes"] = {
        "pilot_a_sha256": _sha256(pilot_a_path),
        "pilot_b_sha256": _sha256(pilot_b_path),
        "economics_sha256": _sha256(economics_path),
    }
    economics_snapshot = economics.get("economics_snapshot", {}) if isinstance(economics, dict) else {}
    optimization = economics.get("optimization", {}) if isinstance(economics, dict) else {}
    optimization_final = optimization.get("final", {}) if isinstance(optimization, dict) else {}
    economics_thresholds_met = bool(optimization_final.get("thresholds_met", False))
    report["independent_evidence"] = {
        "economics_snapshot": economics_snapshot,
        "optimization_final": optimization_final,
        "economics_thresholds_met": economics_thresholds_met,
    }
    if report["decision"] == "GO" and not economics_thresholds_met:
        report["decision"] = "NO_GO"
        report["blocking_reasons"] = list(report.get("blocking_reasons", [])) + ["Economics hardening thresholds not met"]
    return report


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# S51 Gate Review v3",
        "",
        f"- Decision: **{report['decision']}**",
        f"- Gate version: `{report.get('gate_version', 'v3')}`",
        "",
        "## Checks",
    ]
    for check in report.get("checks", []):
        status = "PASS" if check.get("passed") else "FAIL"
        lines.append(f"- [{status}] {check.get('criterion')}")
    lines.append("")
    lines.append("## Blocking Reasons")
    if report.get("blocking_reasons"):
        for reason in report["blocking_reasons"]:
            lines.append(f"- {reason}")
    else:
        lines.append("- None")
    lines.append("")
    lines.append("## Metrics Snapshot")
    for key, value in report.get("metrics_snapshot", {}).items():
        lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append("## Independent Evidence")
    evidence = report.get("independent_evidence", {})
    lines.append(f"- economics_thresholds_met: {evidence.get('economics_thresholds_met')}")
    for key, value in report.get("source_hashes", {}).items():
        lines.append(f"- {key}: `{value}`")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate S51 gate review v3 with independent economics evidence.")
    parser.add_argument("--pilot-a", type=Path, default=DEFAULT_PILOT_A)
    parser.add_argument("--pilot-b", type=Path, default=DEFAULT_PILOT_B)
    parser.add_argument("--economics", type=Path, default=DEFAULT_ECONOMICS)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_MD)
    args = parser.parse_args()

    report = build_review(pilot_a_path=args.pilot_a, pilot_b_path=args.pilot_b, economics_path=args.economics)
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.out_md.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
