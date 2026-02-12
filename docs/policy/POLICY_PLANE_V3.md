# Policy Plane v3 (S33)

## Scope Delivered
- ABAC context checks integrated into runtime policy decisions.
- Signed policy decisions for integrity and replay-safe verification.
- Explainability envelope attached to each policy decision.

## ABAC Context Model
- `principal`:
  - `tenant_id`
  - `allowed_actions`
  - `mfa_present`
- `resource`:
  - `tenant_id`
- `environment`:
  - `requires_mfa`

## ABAC Violations
- `abac.tenant_mismatch`
- `abac.action_not_allowed`
- `abac.mfa_required`

## Decision Signing
- Signature field: `decision_signature`
- Algorithm label: `sha256(secret+payload)`
- Verification helper: `verify_decision_signature(decision)`

## Explainability
- `explainability.violation_codes`
- `explainability.warning_codes`
- `explainability.allow_codes`
- `explainability.evaluated_fields`

## Notes
- Signing secret source: `AGENTHUB_POLICY_SIGNING_SECRET` (fallback default for local/dev).
- Deterministic decision structure preserved for repeatable policy/eval tests.
