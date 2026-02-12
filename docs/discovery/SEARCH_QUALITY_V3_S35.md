# Search Quality v3 (S35)

## Scope Delivered
- Added discovery quality evaluation harness for live index runtime:
  - NDCG@K
  - MRR
  - latency mean/p95
- Added reproducible S35 quality dataset:
  - `tools/discovery/quality_dataset_s35.json`
- Added benchmark runner:
  - `tools/discovery/quality_v3.py`
- Added test gate:
  - `tests/discovery/test_quality_v3.py`

## Quality Gate Targets
- `ndcg_at_k_mean >= 0.65`
- `mrr_mean >= 0.65`
- `latency_p95_ms < 250`

## Output Artifact
- Default benchmark output:
  - `data/discovery/s35_quality_results.json`

## Notes
- Harness runs against discovery live index service (registry + adapter ingestion).
- Metrics are deterministic under current fixture dataset and policy constraints.
