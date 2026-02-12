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

## API Visibility Contract
Registry API responses expose eval summaries for UI use:
- `GET /v1/agents/{id}` -> `eval_summary`
- `GET /v1/agents/{id}/versions` -> per-version `eval_summary`
- `GET /v1/agents/{id}/versions/{v}` -> `eval_summary`
