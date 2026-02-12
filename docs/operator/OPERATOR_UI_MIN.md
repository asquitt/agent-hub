# D07 Minimum Operator UI

## Scope Implemented (S11)
- Operator console page: `GET /operator`
- Operator dashboard API: `GET /v1/operator/dashboard`
- Admin-only refresh action: `POST /v1/operator/refresh`

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
  - Dashboard returns all five required observability sections.
- Access control:
  - Viewer blocked from admin refresh endpoint.
  - Forced role elevation blocked.
  - Admin refresh allowed.
