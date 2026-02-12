# D07 Minimum Operator UI

## Scope Implemented (S11)
- Operator console page: `GET /operator`
- Operator dashboard API: `GET /v1/operator/dashboard`
- Admin-only refresh action: `POST /v1/operator/refresh`

## S42 Operator UX v2 Additions
- Timeline explorer:
  - `GET /v1/operator/dashboard` now includes `timeline` section built from delegation lifecycle + audit events.
- Policy/cost overlay:
  - Dashboard includes `policy_cost_overlay` section with aggregate cost/risk counters and delegation-level governance cards.
- Replay diagnostics:
  - Added `GET /v1/operator/replay/{delegation_id}` for single-delegation event replay and cost/policy context.
- UI updates:
  - Operator page now includes timeline/policy overlay panels and replay loader workflow.

## Minimum Workflows
1. Search visibility: query capability search and inspect top results.
2. Agent detail visibility: inspect namespace, status, latest version, capability count.
3. Eval visibility: show latest eval row or pending fallback.
4. Trust visibility: show trust score/tier/badge breakdown.
5. Delegation visibility: show most recent delegation lifecycle records.

## Role Model
- `viewer`: may read dashboard.
- `admin`: may read dashboard and trigger refresh action.
- Escalation protection: a viewer principal cannot request admin role.

## Test Coverage
- Journey smoke:
  - UI page renders.
  - Dashboard returns timeline and policy/cost overlay sections in addition to baseline observability sections.
  - Replay endpoint returns event timeline for delegation diagnostics.
- Access control:
  - Viewer blocked from admin refresh endpoint.
  - Forced role elevation blocked.
  - Admin refresh allowed.
