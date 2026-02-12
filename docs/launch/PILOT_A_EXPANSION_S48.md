# Pilot Expansion A (S48)

## Scope
S48 expands Pilot A reporting depth with:
- connector-level workload coverage metrics,
- planned workload volume accounting,
- ROI metrics (hours saved, labor savings, platform spend, net ROI),
- richer pilot comparison deltas.

## Tooling Changes
- `tools/pilots/export_pilot_metrics.py`
  - Adds pilot profile modeling for connector mix and workload volumes.
  - Adds `metrics.connectors`, `metrics.workloads`, and `metrics.roi`.
  - Keeps existing reliability/cost/trust/marketplace metrics.
- `tools/pilots/compare_pilots.py`
  - Adds deltas for connector coverage and ROI.

## Pilot A Connector Profile
- `salesforce-crm`
- `zendesk-support`
- `snowflake-warehouse`
- `slack-ops`
- `jira-delivery`

## Key S48 KPIs
- `metrics.connectors.coverage_ratio >= 0.80`
- `metrics.workloads.planned_weekly_tasks >= 120`
- `metrics.roi.net_roi_usd > 0`
- Existing reliability guardrails remain enforced.
