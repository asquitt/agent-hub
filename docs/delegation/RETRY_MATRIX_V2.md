# Delegation Retry Matrix v2 (S19)

## Failure Taxonomy
- `transient_network_error`
- `delegate_timeout`
- `policy_denied`
- `hard_stop_budget`

## Retry Rules
| Failure Class | Max Retries | Backoff (ms) | Idempotency Required |
|---|---:|---|---|
| transient_network_error | 2 | 100, 250 | Yes |
| delegate_timeout | 1 | 200 | Yes |
| policy_denied | 0 | none | Yes |
| hard_stop_budget | 0 | none | Yes |

## Notes
- All delegation writes are replay-safe only when `Idempotency-Key` is present.
- Non-retriable classes are hard policy failures and require request mutation or explicit user reauthorization.
