from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parents[2]


def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def build_metrics() -> dict:
    delegations = _load_json(ROOT / "data" / "delegations" / "records.json", [])
    costs = _load_json(ROOT / "data" / "cost" / "events.json", [])
    trust_scores = _load_json(ROOT / "data" / "trust" / "scores.json", [])
    incidents = _load_json(ROOT / "data" / "trust" / "incidents.json", [])
    contracts = _load_json(ROOT / "data" / "marketplace" / "contracts.json", [])

    total_delegations = len(delegations)
    completed_delegations = sum(1 for row in delegations if row.get("status") == "completed")
    hard_stops = sum(1 for row in delegations if row.get("status") == "failed_hard_stop")
    reliability = (completed_delegations / total_delegations) if total_delegations else 0.0

    estimated = [float(row.get("estimated_cost_usd", 0.0)) for row in delegations if row.get("estimated_cost_usd") is not None]
    actual = [float(row.get("actual_cost_usd", 0.0)) for row in delegations if row.get("actual_cost_usd") is not None]
    cost_variance = 0.0
    if estimated and actual and len(estimated) == len(actual):
        deltas = [abs(a - e) / max(e, 1e-6) for e, a in zip(estimated, actual)]
        cost_variance = mean(deltas)

    unresolved_incidents = sum(1 for row in incidents if not row.get("resolved"))
    avg_trust = mean([float(row.get("score", 0.0)) for row in trust_scores]) if trust_scores else 0.0
    settled_contracts = sum(1 for row in contracts if row.get("status") == "settled")
    metering_events = len(costs)

    return {
        "reliability": {
            "delegation_success_rate": round(reliability, 6),
            "total_delegations": total_delegations,
            "completed_delegations": completed_delegations,
            "hard_stop_count": hard_stops,
        },
        "cost": {
            "avg_relative_cost_variance": round(cost_variance, 6),
            "metering_events": metering_events,
        },
        "trust": {
            "avg_trust_score": round(avg_trust, 6),
            "unresolved_incidents": unresolved_incidents,
        },
        "marketplace": {
            "settled_contracts": settled_contracts,
            "total_contracts": len(contracts),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Export weekly pilot metrics snapshot.")
    parser.add_argument("--pilot-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    payload = {
        "pilot_id": args.pilot_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metrics": build_metrics(),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
