from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _metric(payload: dict, *path: str, default=0.0):
    current = payload
    for part in path:
        if not isinstance(current, dict):
            return default
        current = current.get(part)
        if current is None:
            return default
    return current


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
                float(_metric(b_metrics, "reliability", "delegation_success_rate"))
                - float(_metric(a_metrics, "reliability", "delegation_success_rate")),
                6,
            ),
            "avg_relative_cost_variance": round(
                float(_metric(b_metrics, "cost", "avg_relative_cost_variance"))
                - float(_metric(a_metrics, "cost", "avg_relative_cost_variance")),
                6,
            ),
            "avg_trust_score": round(
                float(_metric(b_metrics, "trust", "avg_trust_score")) - float(_metric(a_metrics, "trust", "avg_trust_score")),
                6,
            ),
            "unresolved_incidents": int(_metric(b_metrics, "trust", "unresolved_incidents", default=0))
            - int(_metric(a_metrics, "trust", "unresolved_incidents", default=0)),
            "connector_coverage_ratio": round(
                float(_metric(b_metrics, "connectors", "coverage_ratio")) - float(_metric(a_metrics, "connectors", "coverage_ratio")),
                6,
            ),
            "planned_weekly_tasks": int(_metric(b_metrics, "workloads", "planned_weekly_tasks", default=0))
            - int(_metric(a_metrics, "workloads", "planned_weekly_tasks", default=0)),
            "net_roi_usd": round(
                float(_metric(b_metrics, "roi", "net_roi_usd")) - float(_metric(a_metrics, "roi", "net_roi_usd")),
                6,
            ),
            "roi_ratio": round(
                float(_metric(b_metrics, "roi", "roi_ratio")) - float(_metric(a_metrics, "roi", "roi_ratio")),
                6,
            ),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(comparison, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(comparison, indent=2))


if __name__ == "__main__":
    main()
