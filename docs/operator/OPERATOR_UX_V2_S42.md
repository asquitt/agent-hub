# Operator UX v2 (S42)

## Goals
- Provide actionable delegation timeline diagnostics.
- Overlay policy and cost governance state for rapid triage.
- Support deterministic replay workflow for specific delegation IDs.

## API Surfaces
- Dashboard: `GET /v1/operator/dashboard`
  - new sections:
    - `timeline`
    - `policy_cost_overlay`
- Replay endpoint: `GET /v1/operator/replay/{delegation_id}`

## Timeline Model
Events are normalized from:
- delegation lifecycle stages,
- delegation audit trail entries.

Each event carries:
- timestamp,
- delegation id,
- event type/name,
- event details payload.

## Policy/Cost Overlay
Overlay includes:
- aggregate estimated/actual cost totals,
- hard-stop and pending-reauthorization counts,
- soft-alert count,
- delegation cards with budget ratio/state and policy decision summary.

## Replay Workflow
Replay response provides:
- queue state,
- policy decision,
- budget controls,
- per-delegation timeline,
- cost overlay summary for the selected delegation.

## UI
`/operator` now renders dedicated cards for:
- policy/cost overlay,
- timeline explorer,
- replay diagnostics panel with delegation-id loader.

## Validation
- Operator smoke test verifies new sections and replay workflow.
- Role boundaries remain unchanged (`viewer` read-only, `admin` for refresh action).
