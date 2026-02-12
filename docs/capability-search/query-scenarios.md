# Capability Search Query Scenarios (D02)

## Purpose
Concrete scenarios used to validate search, contract matching, and recommendation behavior against mock registry data.

## Scenario Matrix (10)

### Q01 - NL Search: invoice extraction under trust guard
- Endpoint: `POST /v1/capabilities/search`
- Query: "extract invoice totals"
- Filters: `min_trust_score=0.8`, `max_cost_usd=0.02`, `allowed_protocols=[MCP]`
- Expected behavior:
  - Returns invoice/receipt transformation capabilities that satisfy trust + cost + protocol.
  - Top result should be `invoice-summarizer/summarize-invoice`.

### Q02 - NL Search: support triage with latency constraint
- Endpoint: `POST /v1/capabilities/search`
- Query: "classify support ticket severity"
- Filters: `max_latency_ms=100`, `min_trust_score=0.8`
- Expected behavior:
  - `support-orchestrator/classify-ticket` ranks above slower action-oriented capabilities.

### Q03 - NL Search: privileged action denied by permission requirement
- Endpoint: `POST /v1/capabilities/search`
- Query: "execute payment"
- Filters: `required_permissions=[payments.execute]`, `min_trust_score=0.9`
- Expected behavior:
  - Only payment-capable candidates with explicit permission scope survive gating.
  - Non-privileged document agents are excluded.

### Q04 - Schema Match: exact contract for invoice summarize
- Endpoint: `POST /v1/capabilities/match`
- Input schema required fields: `invoice_text`
- Output schema required fields: `vendor,total`
- Filters: `compatibility_mode=exact`
- Expected behavior:
  - Returns only exact contract matches.
  - `invoice-summarizer/summarize-invoice` included as exact.

### Q05 - Schema Match: backward compatible with richer output
- Endpoint: `POST /v1/capabilities/match`
- Input schema required fields: `invoice_text`
- Output schema required fields: `vendor,total`
- Filters: `compatibility_mode=backward_compatible`
- Expected behavior:
  - Exact + compatible candidates returned.
  - Candidates returning supersets of requested output are allowed.

### Q06 - Agent capability listing
- Endpoint: `GET /v1/agents/{id}/capabilities`
- Agent id: `support-orchestrator`
- Expected behavior:
  - Returns full declared capability set for the agent.
  - Includes both `classify-ticket` and `apply-remediation`.

### Q07 - Recommendation: onboarding pipeline gaps
- Endpoint: `POST /v1/capabilities/recommend`
- Current capability ids: `validate-identity`, `run-policy-screening`
- Task: "complete customer onboarding with billing setup"
- Expected behavior:
  - Recommends `billing-provisioner/provision-billing` as complement.
  - Includes recommendation reason `coverage_gap`.

### Q08 - Recommendation: support workflow hardening
- Endpoint: `POST /v1/capabilities/recommend`
- Current capability ids: `classify-ticket`
- Task: "resolve customer incidents automatically"
- Filters: `min_trust_score=0.8`
- Expected behavior:
  - Suggests remediation capability with trust-qualified candidates.

### Q09 - Negative: malformed filter payload
- Endpoint: `POST /v1/capabilities/search`
- Invalid payload: `max_latency_ms=-5`
- Expected behavior:
  - Request rejected with validation error (`400` or `422`).

### Q10 - Negative: no candidate passes policy constraints
- Endpoint: `POST /v1/capabilities/search`
- Query: "provision billing"
- Filters: `min_trust_score=0.95`, `max_cost_usd=0.01`
- Expected behavior:
  - Empty result set with no unsafe fallback.

## Verification Coverage Mapping
- NL search behavior: Q01-Q03
- Schema match behavior: Q04-Q05
- Recommendation behavior: Q07-Q08
- Negative/error behavior: Q09-Q10
