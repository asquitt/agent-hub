# Trust Scoring Core (D11)

## Overview
Trust scoring combines eval, usage, reputation, community, security, freshness, and incident penalties into a dynamic 0-100 score.

## Weights
- Eval pass rate: 30%
- Usage success rate: 20%
- Publisher reputation: 15%
- Community validation: 10%
- Security audit: 10%
- Freshness: 10%
- Incident penalty: -20%

## Tier Mapping
- Unverified: 0-39 (Gray)
- Community: 40-59 (Bronze)
- Verified: 60-79 (Silver)
- Trusted: 80-89 (Gold)
- Certified: 90-100 (Platinum)

## Anti-Gaming Controls
- Sybil resistance:
  - New accounts get a 30-day trust accumulation delay multiplier.
- Publisher reputation gating:
  - Requires minimum 3 agents and independent usage before full publisher signal applies.
- Eval manipulation detection:
  - Canary failures clamp security signal and set `canary_failure_detected` flag.
- Review fraud resistance:
  - Only verified-usage reviews are included in community signal.

## S21 Trust Graph v2 Enhancements
- Recency weighting:
  - Usage, review, and security evidence apply decay weights so recent evidence contributes more than stale evidence.
- Evidence quality weighting:
  - Usage signal weights latency/cost quality.
  - Review signal weights `evidence_quality` and optional reviewer reputation.
  - Security signal weights audit score by recency + evidence quality.
- Suspicious-pattern detection:
  - Flags low reviewer diversity (`low_reviewer_diversity_detected`).
  - Flags suspicious positive review bursts (`review_burst_detected`).
  - Applies mismatch penalty when very high community sentiment is not supported by runtime usage.
- Manipulation penalty:
  - Additional bounded penalty term (`manipulation_penalty_weight`) is applied to reduce adversarial score inflation.

## S41 Trust Graph v3 Enhancements
- Abuse graph inputs:
  - Added `interaction_graph` evidence stream (`source_agent_id`, `target_agent_id`, `source_owner`, `edge_type`, `occurred_at`).
- Collusion detection:
  - Flags low source diversity in inbound interaction patterns.
  - Flags reciprocal interaction loops indicative of ring behavior.
- Sybil-cluster detection:
  - Flags clusters where a majority of interaction sources belong to very new publisher accounts.
- Reputation decay tuning:
  - Applies additional penalty for stale agents with aged eval/usage/review/security evidence.
- New breakdown fields:
  - `graph_abuse_penalty`
  - `reputation_decay_penalty`

## API Contract
- `GET /v1/agents/{id}/trust` returns:
  - score, tier, badge, breakdown, anti-gaming flags, and weights

## Recalculation Triggers
- New eval results (reflected in eval signal)
- Usage events (success-rate updates)
- Security audits / incidents / reviews updates

## Operator CLI
```bash
python3 tools/trust/recompute_trust.py --agent-id @demo:invoice-summarizer --owner owner-dev
```
