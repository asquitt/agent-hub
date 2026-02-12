# Federated Execution Gateway (S22)

## Goal
Allow centralized discovery/trust while keeping execution in enterprise-local domains.

## API
- `POST /v1/federation/execute`
- `GET /v1/federation/audit`

## Gateway Contract
- Domain authentication required (`domain_id` + `domain_token`).
- Policy propagation required (`policy_context.decision=allow`).
- Budget constraint required (`estimated_cost_usd <= max_budget_usd`).
- Secret isolation:
  - Inline secrets in payload are blocked.
  - Only references (for example vault URIs) should traverse gateway boundaries.

## Result Attestation Format
- `attestation_hash`
- `input_hash`
- `output_hash`
- `timestamp`
- `domain_id`
- `actor`

## Audit Record Requirements
- actor
- domain_id
- task_spec
- input_hash
- output_hash
- attestation_hash
- estimated_cost_usd
- max_budget_usd
- policy_context_hash
- timestamp
