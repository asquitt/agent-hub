# D15 Shared Knowledge Registry

## Scope Implemented (S14)
- `POST /v1/knowledge/contribute`
- `GET /v1/knowledge/query`
- `POST /v1/knowledge/validate/{entry_id}`

## Core Controls
- Poisoning defense:
  - Rejects oversized content.
  - Rejects known prompt-injection style patterns.
- Provenance integrity:
  - SHA-256 provenance hash generated from title/content/source URI.
- Confidence decay:
  - Confidence decreases with age to prevent stale knowledge dominance.
- Cross-validation:
  - Validator verdicts adjust confidence (positive/negative weighting).

## Output Fields
- `entry_id`
- `provenance_hash`
- `confidence`
- `validations[]`
- `created_at` / `updated_at`
