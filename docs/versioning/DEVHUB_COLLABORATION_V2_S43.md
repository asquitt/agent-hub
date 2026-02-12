# DevHub Collaboration v2 (S43)

## Scope
S43 introduces governance-oriented review gates and release promotion controls for agent version workflows.

## Persistence
- Runtime DB scope: `devhub`
- Tables:
  - `devhub_release_reviews`
  - `devhub_release_decisions`
  - `devhub_promotions`

## Workflow
1. Create review request for `agent_id + version`.
2. Admin actors submit one decision each (`approve`/`reject`).
3. Review state transitions:
   - `pending` -> `approved` when approvals reach threshold.
   - `pending` -> `rejected` on first rejection.
4. Approved reviews can be promoted once.
5. Promotion marks review state `promoted` and records immutable promotion event.

## API
- `POST /v1/devhub/reviews`
- `GET /v1/devhub/reviews`
- `GET /v1/devhub/reviews/{review_id}`
- `POST /v1/devhub/reviews/{review_id}/decision`
- `POST /v1/devhub/reviews/{review_id}/promote`
- `GET /v1/devhub/promotions`

## Governance Rules
- Decision and promotion actions require admin operator role.
- A reviewer can only decide once per review.
- Rejected or promoted reviews are terminal.
- Promotion is blocked unless review status is `approved`.

## Verification
- End-to-end collaboration tests cover:
  - pending -> approved -> promoted path,
  - viewer/admin role boundaries,
  - rejection and duplicate-vote blocking,
  - promotion denial for rejected reviews.
