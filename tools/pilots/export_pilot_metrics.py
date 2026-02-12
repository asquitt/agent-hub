from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parents[2]

PILOT_PROFILES = {
    "pilot-a": {
        "labor_rate_usd_per_hour": 95.0,
        "platform_cost_per_task_usd": 2.1,
        "connectors": [
            {"connector_id": "salesforce-crm", "category": "crm", "baseline_minutes": 18, "automated_minutes": 6},
            {"connector_id": "zendesk-support", "category": "support", "baseline_minutes": 14, "automated_minutes": 4},
            {"connector_id": "snowflake-warehouse", "category": "data", "baseline_minutes": 22, "automated_minutes": 8},
            {"connector_id": "slack-ops", "category": "collaboration", "baseline_minutes": 7, "automated_minutes": 2},
            {"connector_id": "jira-delivery", "category": "delivery", "baseline_minutes": 16, "automated_minutes": 5},
        ],
        "workloads": [
            {"workload_id": "incident-triage", "connector_id": "zendesk-support", "weekly_tasks": 42, "criticality": "high"},
            {"workload_id": "case-enrichment", "connector_id": "salesforce-crm", "weekly_tasks": 34, "criticality": "high"},
            {"workload_id": "knowledge-sync", "connector_id": "snowflake-warehouse", "weekly_tasks": 24, "criticality": "medium"},
            {"workload_id": "ops-alert-routing", "connector_id": "slack-ops", "weekly_tasks": 40, "criticality": "medium"},
            {"workload_id": "release-risk-brief", "connector_id": "jira-delivery", "weekly_tasks": 20, "criticality": "medium"},
        ],
    },
    "pilot-b": {
        "labor_rate_usd_per_hour": 88.0,
        "platform_cost_per_task_usd": 2.3,
        "connectors": [
            {"connector_id": "hubspot-crm", "category": "crm", "baseline_minutes": 16, "automated_minutes": 7},
            {"connector_id": "freshdesk-support", "category": "support", "baseline_minutes": 13, "automated_minutes": 5},
            {"connector_id": "bigquery-warehouse", "category": "data", "baseline_minutes": 20, "automated_minutes": 9},
            {"connector_id": "teams-ops", "category": "collaboration", "baseline_minutes": 8, "automated_minutes": 3},
        ],
        "workloads": [
            {"workload_id": "support-escalation", "connector_id": "freshdesk-support", "weekly_tasks": 36, "criticality": "high"},
            {"workload_id": "pipeline-hygiene", "connector_id": "hubspot-crm", "weekly_tasks": 28, "criticality": "medium"},
            {"workload_id": "weekly-forecast-sync", "connector_id": "bigquery-warehouse", "weekly_tasks": 18, "criticality": "medium"},
            {"workload_id": "incident-broadcast", "connector_id": "teams-ops", "weekly_tasks": 30, "criticality": "medium"},
        ],
    },
}


def _load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def build_metrics(pilot_id: str) -> dict:
    delegations = _load_json(ROOT / "data" / "delegations" / "records.json", [])
    costs = _load_json(ROOT / "data" / "cost" / "events.json", [])
    trust_scores = _load_json(ROOT / "data" / "trust" / "scores.json", [])
    incidents = _load_json(ROOT / "data" / "trust" / "incidents.json", [])
    contracts = _load_json(ROOT / "data" / "marketplace" / "contracts.json", [])
    profile = PILOT_PROFILES[pilot_id]

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

    connectors = profile["connectors"]
    workloads = profile["workloads"]
    connector_map = {row["connector_id"]: row for row in connectors}
    connector_volumes: dict[str, int] = {row["connector_id"]: 0 for row in connectors}
    planned_weekly_tasks = 0
    baseline_minutes_total = 0
    automated_minutes_total = 0
    for workload in workloads:
        connector_id = workload["connector_id"]
        weekly_tasks = int(workload["weekly_tasks"])
        planned_weekly_tasks += weekly_tasks
        connector_volumes[connector_id] = connector_volumes.get(connector_id, 0) + weekly_tasks
        connector = connector_map.get(connector_id, {})
        baseline_minutes_total += weekly_tasks * int(connector.get("baseline_minutes", 0))
        automated_minutes_total += weekly_tasks * int(connector.get("automated_minutes", 0))

    active_connectors = len([connector_id for connector_id, volume in connector_volumes.items() if volume > 0])
    configured_connectors = len(connectors)
    connector_coverage_ratio = (active_connectors / configured_connectors) if configured_connectors else 0.0

    hours_saved = max(0.0, (baseline_minutes_total - automated_minutes_total) / 60.0)
    labor_savings_usd = hours_saved * float(profile["labor_rate_usd_per_hour"])
    platform_spend_usd = planned_weekly_tasks * float(profile["platform_cost_per_task_usd"])
    net_roi_usd = labor_savings_usd - platform_spend_usd
    roi_ratio = net_roi_usd / max(platform_spend_usd, 1e-6)

    return {
        "reliability": {
            "delegation_success_rate": round(reliability, 6),
            "total_delegations": total_delegations,
            "completed_delegations": completed_delegations,
            "hard_stop_count": hard_stops,
            "planned_workload_tasks": planned_weekly_tasks,
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
        "connectors": {
            "configured_count": configured_connectors,
            "active_count": active_connectors,
            "coverage_ratio": round(connector_coverage_ratio, 6),
            "by_connector": [
                {
                    "connector_id": row["connector_id"],
                    "category": row["category"],
                    "weekly_tasks": connector_volumes.get(row["connector_id"], 0),
                }
                for row in connectors
            ],
        },
        "workloads": {
            "planned_weekly_tasks": planned_weekly_tasks,
            "profiles": workloads,
        },
        "roi": {
            "labor_rate_usd_per_hour": float(profile["labor_rate_usd_per_hour"]),
            "platform_cost_per_task_usd": float(profile["platform_cost_per_task_usd"]),
            "estimated_hours_saved": round(hours_saved, 6),
            "estimated_labor_savings_usd": round(labor_savings_usd, 6),
            "estimated_platform_spend_usd": round(platform_spend_usd, 6),
            "net_roi_usd": round(net_roi_usd, 6),
            "roi_ratio": round(roi_ratio, 6),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Export weekly pilot metrics snapshot.")
    parser.add_argument("--pilot-id", required=True, choices=sorted(PILOT_PROFILES.keys()))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    payload = {
        "pilot_id": args.pilot_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metrics": build_metrics(args.pilot_id),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
