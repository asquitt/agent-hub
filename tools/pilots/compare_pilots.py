from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare pilot KPI exports.")
    parser.add_argument("--pilot-a", type=Path, required=True)
    parser.add_argument("--pilot-b", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    a = _load(args.pilot_a)
    b = _load(args.pilot_b)
    a_metrics = a["metrics"]
    b_metrics = b["metrics"]

    comparison = {
        "pilot_a": a["pilot_id"],
        "pilot_b": b["pilot_id"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "deltas": {
            "delegation_success_rate": round(
                b_metrics["reliability"]["delegation_success_rate"] - a_metrics["reliability"]["delegation_success_rate"], 6
            ),
            "avg_relative_cost_variance": round(
                b_metrics["cost"]["avg_relative_cost_variance"] - a_metrics["cost"]["avg_relative_cost_variance"], 6
            ),
            "avg_trust_score": round(b_metrics["trust"]["avg_trust_score"] - a_metrics["trust"]["avg_trust_score"], 6),
            "unresolved_incidents": b_metrics["trust"]["unresolved_incidents"] - a_metrics["trust"]["unresolved_incidents"],
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(comparison, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(comparison, indent=2))


if __name__ == "__main__":
    main()
