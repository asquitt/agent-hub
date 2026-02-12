# Economics Hardening (S50)

## Scope
S50 introduces a deterministic economics optimization loop for pilot outputs.

## New Components
- `src/economics/hardening.py`
  - Aggregates economics signals across pilot exports.
  - Evaluates margin/variance/task thresholds.
  - Runs optimization iterations with explicit economic levers.
- `tools/pilots/economics_hardening.py`
  - Produces an optimization report from pilot A/B exports.

## Thresholds
- Contribution margin ratio >= `0.20`
- p95 cost variance <= `0.15`
- Multi-agent task volume >= `100`

## Optimization Loop Levers
- Reduce platform cost per task (improves margin).
- Tighten batching/guardrails (reduces variance).
- Recommend workload expansion when task-floor is not met.

## Gate Integration
`tools/gate/review_v2.py` now derives economics-sensitive metrics using:
- complexity-adjusted reliability,
- ROI ratio,
- contribution margin proxy,
- aggregated multi-agent workload volume.
