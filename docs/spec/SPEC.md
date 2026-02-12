# AgentHub Agent Manifest Specification v0.1

## Purpose
`agent.yaml` is the canonical internal contract for AgentHub interoperability. The manifest is protocol-neutral and projects to protocol adapters (MCP first, then A2A) without forking business logic.

Schema source of truth:
- `specs/manifest/agent-manifest-spec-v0.1.yaml`

## Top-Level Shape
Required sections:
- `schema_version` (must be `0.1`)
- `identity`
- `capabilities`
- `interfaces`
- `trust`
- `runtime`

Optional sections:
- `requirements`
- `composition`
- `provenance`

All objects are strict (`additionalProperties: false`) unless intentionally declared extensible.

## Section Semantics

### `identity`
- Stable agent metadata and release identity.
- `identity.version` must be semantic versioning.

### `requirements`
- Shared execution prerequisites.
- Secrets are references only (`env://`, `vault://`, `kms://`); inline secret values are disallowed.
- Global permission scope declarations are explicit.

### `capabilities`
- Unit of delegation and discovery.
- Every capability declares:
  - input schema
  - output schema
  - supported protocols
  - side-effect level
  - idempotency requirements
- For write-capable capabilities (`side_effect_level` = `low|high`), `idempotency_key_required` must be `true`.

### `interfaces`
- Transport/protocol exposure details.
- `protocol` enum: `MCP`, `A2A`, `HTTP`, `CLI`, `INTERNAL`.
- Non-`INTERNAL` interfaces require `endpoint`.
- Privileged interfaces require explicit `permissions`.

### `trust`
Policy-first guardrails enforced before semantic ranking:
- `minimum_trust_score`
- `allowed_trust_sources`
- `policy` metadata
- budget guardrails
- credential policy

Budget thresholds are fixed for v0.1:
- `soft_alert_pct = 80`
- `reauthorization_pct = 100`
- `hard_stop_pct = 120`

### `composition`
- Optional deterministic orchestration graph/pipeline declaration.
- `pipeline|graph` requires at least two steps.

### `runtime`
Reliability defaults:
- idempotency required
- replay-safe execution required
- privileged action/cost/latency observability required

### `provenance`
- Source lineage and audit context.

## Validation Contract
Validation has two layers:
1. JSON Schema (Draft 2020-12) structural validation.
2. Deterministic policy checks for security constraints not fully represented by schema keywords, including secret-inline detection.

## CLI Contract
Validator command:
- `python3 tools/manifest/validate_manifest.py <manifest-path>`
- `python3 tools/manifest/validate_manifest.py manifest validate <manifest-path>`

Exit codes:
- `0` valid
- `1` validation failure
- `2` usage/runtime error

## Compatibility Notes
- Adapter-facing documents:
  - `docs/spec/a2a-mapping.md`
  - `docs/spec/mcp-mapping.md`
- Unsupported protocol fields must be preserved as metadata on projection where possible; otherwise they are dropped with explicit adapter warnings.
