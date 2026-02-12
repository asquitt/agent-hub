# S37 Reliability/SRE Controls

## Scope
S37 introduces runtime reliability governance for delegation using:
- error-budget accounting against delegation success-rate SLO,
- p95 latency SLO checks,
- circuit-breaker state derivation (`closed`, `half_open`, `open`),
- alert emission for error-budget, latency, and hard-stop pressure.

## Dashboard API
- Endpoint: `GET /v1/reliability/slo-dashboard`
- Auth: API key / bearer auth (`require_api_key`)
- Query params:
  - `window_size` (default `50`, range `1..1000`)

### Response Sections
- `policy`: active SRE thresholds used by runtime governance.
- `window`: evaluated sample size.
- `metrics`: success/error/hard-stop rates and p95 latency.
- `error_budget`: allowed vs observed errors and burn ratio.
- `circuit_breaker`: current breaker state and governance action.
- `alerts`: active warnings/critical alerts.

## Delegation Runtime Enforcement
`POST /v1/delegations` now evaluates reliability dashboard state before policy/delegation execution.
When breaker state is `open`:
- request is rejected with `503`,
- idempotency reservation is cleared,
- response includes breaker state and active alerts for operator triage.

## Governance Defaults
- success-rate SLO: `99%`
- latency p95 SLO: `3000 ms`
- minimum samples before enforcement: `10`
- open thresholds:
  - error rate `>= 30%`
  - hard-stop rate `>= 20%`
  - latency p95 `> 1.5x` SLO

## Test Coverage
- Healthy-load dashboard remains `closed` without alerts.
- Chaos/load simulation triggers `open` state and alert set.
- Delegation API blocks new requests when breaker is `open`.
