# Delegation Protocol Core (D13)

## Lifecycle Stages
Implemented stages in order:
1. `discovery`
2. `negotiation`
3. `execution` (sandboxed temp environment)
4. `delivery`
5. `settlement`
6. `feedback`

## Budget Controls
- Hard ceiling: reject delegation if `estimated_cost_usd > max_budget_usd`.
- Escrow: estimated cost is held from requester balance at negotiation.
- Circuit breaker thresholds:
  - 80%: soft alert
  - 100%: reauthorization required
  - 120%: hard stop
- Settlement returns unused escrow when actual cost is below estimate.

## Audit Trail
Each delegation records metering/audit entries with timestamp, event type, and cost attributes.

## API
- `POST /v1/delegations`
- `GET /v1/delegations/{id}/status`
- `GET /v1/delegations/contract`

## Safety Notes
- Execution stage runs in an isolated temp sandbox model.
- Delivery validates structured output contract marker.
- Feedback stage emits usage signal updates for trust recalculation.

## S19 Delegation Contract v2 Additions
- Idempotency:
  - `POST /v1/delegations` now requires `Idempotency-Key`.
  - Replayed request with same key + same payload returns deterministic cached response.
  - Replayed request with same key + different payload is rejected (`409`).
- Contract metadata (`version=delegation-contract-v2`) includes:
  - SLA target (`p95_latency_ms_target`)
  - Stage timeout settings
  - Retry matrix by failure class
  - Circuit-breaker thresholds (`80/100/120`)

## S36 Delegation Durability Additions
- Durable idempotency:
  - Delegation idempotency keys are persisted in SQLite (`delegation_idempotency`) instead of process memory.
  - Replays now survive runtime reconfigure/restart and remain scoped by owner+tenant.
  - In-flight duplicate storms wait for persisted completion response and return deterministic output.
- Durable queue state:
  - Delegation orchestration state is persisted in `delegation_queue_state`.
  - Queue status now transitions `queued -> running -> settlement_status`.
  - Attempt counters are preserved for replay/restore and incident debugging workflows.
