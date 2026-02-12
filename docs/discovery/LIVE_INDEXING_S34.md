# Discovery Live Indexing (S34)

## Goal
Replace direct mock-engine coupling in discovery runtime with a live capability index that ingests registry manifests and adapter metadata.

## Implemented Components
- `src/discovery/index.py`
  - `LiveCapabilityIndex` with refresh interval control.
  - Source ingestion:
    - Registry manifests (latest version per agent from persistent store).
    - Adapter metadata catalog (`AGENTHUB_ADAPTER_CATALOG_PATH`, default fixture dataset).
  - Merge strategy:
    - Key: `(agent_id, capability_id)`
    - Registry rows override adapter rows for key collisions.

- `src/discovery/service.py`
  - Semantic discovery now scores against live index snapshot.
  - Contract matching and compatibility reports use index snapshot and cached query payloads.
  - Metering events include `index_sources` metadata.
  - `refresh_index(force=True)` available for immediate sync paths.

## Freshness Model
- Index snapshot refresh interval: 5 seconds (configurable in code).
- Force-refresh supported for deterministic ingestion in runtime/tests.

## Policy & Constraints
- Existing policy-first gating remains:
  - Discovery policy decision before ranking.
  - Constraint filtering (cost/latency/trust/protocols/permissions) before scoring.

## Verification
- Registry-backed ingestion verified in:
  - `tests/discovery/test_live_indexing_s34.py`
- Existing discovery SLA/API tests remain green.
