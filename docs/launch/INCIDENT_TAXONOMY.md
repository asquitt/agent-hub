# Incident Taxonomy (S26-S27)

## Severity
- `sev1`: critical outage or policy bypass
- `sev2`: degraded operation with customer impact
- `sev3`: minor issue/no material impact

## Categories
- policy_bypass
- idempotency_failure
- budget_overrun
- delegation_failure
- federation_auth_failure
- trust_manipulation_signal
- marketplace_settlement_dispute

## Required Incident Fields
- incident_id
- occurred_at
- severity
- category
- affected_flow
- resolved (boolean)
- mitigation
- owner
