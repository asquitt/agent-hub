# Cost Governance v2 (S20)

## Budget State Machine
- `ok`: spend ratio `< 0.80`
- `soft_alert`: spend ratio `>= 0.80` and `< 1.00`
- `reauthorization_required`: spend ratio `>= 1.00` and `< 1.20` with auto-reauthorize disabled
- `hard_stop`: spend ratio `>= 1.20`

Spend ratio:

`ratio = actual_or_estimated_cost / max(estimated_budget, epsilon)`

## Guardrail Policy
- 80%: soft alert
- 100%: mandatory reauthorization
- 120%: hard stop

## Metering Integration (S20)
- Metering events are recorded for:
  - `capabilities.search`
  - `capabilities.match`
  - `capabilities.recommend`
  - `discovery.semantic_search`
  - `discovery.contract_match`
  - `discovery.compatibility_report`
  - `delegation.create`
  - `capabilities.lease_promote`
  - `capabilities.lease_promote_denied`
- Metering endpoint:
  - `GET /v1/cost/metering`

## Notes
- Metering in S20 is local-file backed for deterministic testing.
- Distributed aggregation and billing-grade reconciliation remain follow-up scope.
