# Eval Framework Core (D09)

## Scope
This document defines the implemented D09 core eval runner behavior:
- sandboxed Tier 1 contract compliance checks
- deterministic execution seed
- structured metrics persistence
- CLI invocation flow
- API exposure contract for agent detail surfaces

## Implemented Tier
- Tier 1: Contract compliance
- Capability categories covered in suite:
  - `reasoning`
  - `transformation`
  - `action`

## S38 Tier 2 Safety Harness
- Tier 2 suite id: `tier2-safety-v1`
- Safety vectors covered:
  - `prompt_injection`
  - `secret_exfiltration`
  - `jailbreak`
- Harness behavior:
  - deterministic pattern-based detection against adversarial prompt corpus,
  - structured findings with expected-vs-detected categories,
  - false-positive/false-negative accounting,
  - persisted safety-category summaries for regression tracking.

## S39 Tier 3 Outcome Harness
- Tier 3 suite id: `tier3-outcomes-v1`
- Scope:
  - design-partner workflow KPI cases,
  - per-case KPI threshold checks (`gte`/`lte`),
  - critical-case gating and minimum pass-rate enforcement.
- Output:
  - `case_results` with KPI-level pass/fail details,
  - pass-rate and critical-failure metrics,
  - deterministic pass/fail status for promotion gates.

## Runner Guarantees
- Sandbox execution via ephemeral temp directory per run.
- Deterministic seed: `42`.
- Trace capture includes sandbox start event and per-capability contract checks.
- Metrics captured:
  - `total_checks`
  - `passed_checks`
  - `accuracy`
  - `latency_ms`
  - `cost_usd`

## Result Storage
- Path: `data/evals/results.json`
- Structured record fields include:
  - `eval_id`, `agent_id`, `version`, `suite_id`, `tier`, `status`
  - `metrics`
  - `capability_type_results`
  - `trace`
  - timestamps (`started_at`, `completed_at`)

## CLI Integration
Run local suite:
```bash
python3 tools/eval/agenthub_eval.py eval --manifest tests/eval/fixtures/three-capability-agent.yaml --agent-id @eval:demo
```

Run tier-2 safety suite:
```bash
python3 tools/eval/agenthub_eval.py eval --manifest tests/eval/fixtures/three-capability-agent.yaml --agent-id @eval:demo --tier tier2
```

Run tier-3 outcomes suite:
```bash
python3 tools/eval/agenthub_eval.py eval --manifest tests/eval/fixtures/three-capability-agent.yaml --agent-id @eval:demo --tier tier3
```

## API Visibility Contract
Registry API responses expose eval summaries for UI use:
- `GET /v1/agents/{id}` -> `eval_summary`
- `GET /v1/agents/{id}/versions` -> per-version `eval_summary`
- `GET /v1/agents/{id}/versions/{v}` -> `eval_summary`
