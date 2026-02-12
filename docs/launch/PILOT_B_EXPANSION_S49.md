# Pilot Expansion B (S49)

## Scope
S49 expands Pilot B into higher-complexity workload reporting with explicit reliability, ROI, and cost-depth metrics.

## Metric Enhancements
- `metrics.reliability.complexity_adjusted_success_rate`
- `metrics.cost.p95_relative_cost_variance`
- `metrics.cost.cost_per_planned_task_usd`
- `metrics.complexity.avg_workflow_steps`
- `metrics.complexity.avg_cross_system_hops`
- `metrics.complexity.high_risk_workload_ratio`
- `metrics.roi.margin_proxy_ratio`

## Comparison Enhancements
`tools/pilots/compare_pilots.py` now emits deltas for:
- cost p95 variance,
- cost per planned task,
- complexity-adjusted reliability,
- workflow complexity depth,
- margin proxy.

## S49 KPI Intent
- Preserve positive ROI while increasing workload complexity.
- Track cost stability using p95 variance and per-task cost.
- Maintain reliability floors under high-risk workload mix.
