# Capability Search Ranking Algorithm (D02)

## Objective
Rank candidate capabilities for discovery while enforcing policy-first eligibility constraints before any semantic score ordering.

## Policy-First Gate (Hard Filters)
A candidate is rejected if any condition fails:
- Trust below caller threshold (`candidate.trust_score < filters.min_trust_score`)
- Missing required permissions (`required_permissions` not subset of candidate permissions)
- Exceeds latency budget (`candidate.p95_latency_ms > filters.max_latency_ms`)
- Exceeds cost budget (`candidate.estimated_cost_usd > filters.max_cost_usd`)
- Protocol incompatibility (`candidate.protocols` does not intersect `filters.allowed_protocols`)
- Contract incompatibility for match endpoint (`compatibility_mode` = `exact` and schemas differ)

Only policy-compliant candidates enter scoring.

## Composite Score
Weights (default):
- Capability relevance: `0.30`
- Trust score: `0.25`
- Usage volume: `0.15`
- Cost efficiency: `0.10`
- Latency: `0.10`
- Freshness: `0.10`

Formula:

`score = sum(weight_i * signal_i)`

All signals are normalized to `[0, 1]` and all weights are normalized to sum `1.0`.

## Signal Definitions
- Capability relevance:
  - NL search: embedding similarity blended with keyword overlap and schema hint compatibility.
  - Match endpoint: exact/compatible contract score (exact = 1.0, backward-compatible = 0.8).
  - Recommend endpoint: task similarity + complementarity gain.
- Trust score:
  - From D11 trust pipeline (or stub value pre-D11).
- Usage volume:
  - Trailing 30-day normalized call volume.
- Cost efficiency:
  - Inverse normalized expected cost within comparable result set.
- Latency:
  - Inverse normalized recent P95 latency.
- Freshness:
  - Time-decayed recency score from last update and eval recency.

## Tie-Break Order
1. Higher trust score
2. Lower estimated cost
3. Lower p95 latency
4. More recent freshness
5. Lexicographic `agent_id/capability_id` for deterministic output

## Pagination Strategy
- Runtime/agent consumption: cursor pagination (`mode=cursor`) for consistency under changing datasets.
- UI browsing: offset pagination (`mode=offset`) for direct page navigation.
- Response metadata includes mode + next cursor or offset + total.

## Rate Limiting Design
Per-user tiers:
- Anonymous: 60 RPM
- Authenticated: 240 RPM
- Enterprise: 1200 RPM

Per-agent runtime tiers:
- Default runtime identity: 180 RPM
- Trusted runtime identity: 600 RPM

Enforcement model:
- Token bucket per principal and endpoint class.
- Separate quotas for `search`, `match`, and `recommend` to prevent starvation.
- Burst allowance = 2x steady-state RPM for <= 10 seconds.

## Pseudocode
```text
function search(request, candidates):
  weights = normalize_weights(request.ranking_weights or DEFAULT_WEIGHTS)

  eligible = []
  for candidate in candidates:
    if not passes_policy_filters(candidate, request.filters):
      continue

    signals = compute_signals(request, candidate)
    score = dot(weights, signals)
    eligible.append({candidate, signals, score})

  ordered = stable_sort(
    eligible,
    key=(score desc, trust desc, cost asc, latency asc, freshness asc, id asc)
  )

  return paginate(ordered, request.pagination)
```

## Configurability Rules
- Client-supplied `ranking_weights` are optional.
- Server rejects negative weights and normalizes provided weights.
- If any critical signal source is unavailable, fallback scoring uses remaining signals and emits warning metadata.

## Security and Reliability Notes
- Policy filters run before vector similarity ranking to avoid unsafe candidates surfacing.
- Ranking is deterministic for identical input + candidate snapshot.
- Full score breakdown is returned for auditability.

## S18 Upgrade Notes (Capability Search v2)
- Search now emits an explainability block:
  - `why_selected`: semantic + policy + ranking reasons for each returned candidate.
  - `why_rejected`: deterministic policy and semantic rejection reasons for non-returned candidates.
- Added `ranking_mode` support:
  - `baseline`: D02 overlap-based relevance.
  - `v2` (default): weighted semantic relevance with capability-name emphasis and synonym support.
- Benchmark harness:
  - Dataset: `tools/capability_search/benchmark_dataset_s18.json`
  - Script: `tools/capability_search/benchmark.py`
  - Output artifact: `data/capability_search/s18_benchmark_results.json`
