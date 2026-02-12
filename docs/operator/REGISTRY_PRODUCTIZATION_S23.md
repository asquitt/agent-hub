# Registry UX/API Productization (S23)

## New API Flows
- Publish: `POST /v1/agents`
- Fork: `POST /v1/agents/{agent_id}/fork`
- Version compare: `GET /v1/agents/{agent_id}/compare/{base_version}/{target_version}`

## Version Compare Output
- Behavioral diff payload from versioning engine.
- Eval metric deltas (`eval_delta`) to tie behavior changes to quality impact.

## Operator UI
- New page: `GET /operator/versioning`
- Provides a minimal compare UI for:
  - Agent id input
  - Base/target version selection
  - Compare output rendering

## Productization Notes
- Fork endpoint respects namespace ownership and idempotency semantics.
- Compare endpoint preserves deterministic output and existing version retrieval behavior.
