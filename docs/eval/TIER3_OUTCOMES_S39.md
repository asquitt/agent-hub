# Tier-3 Outcome Eval Suite (S39)

## Objective
Measure workflow-level business outcomes for top design-partner use cases and gate promotion with KPI pass-rate thresholds.

## Runner
- Entrypoint: `run_tier3_outcome_eval` in `src/eval/runner.py`
- Suite id: `tier3-outcomes-v1`
- Tier label: `tier3_outcomes`

## Evaluation Model
Each outcome case includes:
- workflow + partner context,
- criticality flag,
- KPI list with `metric`, `operator`, `target`, `observed`.

A case passes only if all KPIs pass.
Global suite gate passes only if:
- case pass rate `>= 0.85`, and
- critical case failures `== 0`.

## Metrics
- `total_cases`, `passed_cases`, `pass_rate`, `pass_rate_gate`
- `total_kpis`, `passed_kpis`, `kpi_pass_rate`
- `critical_cases`, `critical_case_failures`, `critical_pass_rate`
- latency/cost footprint for eval execution.

## CLI
Run tier-3 only:
```bash
python3 tools/eval/agenthub_eval.py eval --manifest tests/eval/fixtures/three-capability-agent.yaml --tier tier3
```

Run composite tiers:
```bash
python3 tools/eval/agenthub_eval.py eval --manifest tests/eval/fixtures/three-capability-agent.yaml --tier all
```

## Regression Tests
- default tier-3 corpus passes KPI gate,
- critical KPI miss forces suite failure,
- CLI returns tier-3 structured output.
