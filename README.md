# AgentHub

AgentHub is a reliability-first interoperability and runtime infrastructure layer for autonomous agents.

## Current Status
- Core segment plan (`S01` through `S16`) is complete.
- Post-core continuation segments (`S17` through `S54`) are complete.
- Source of truth for delivery status and evidence:
  - `docs/DELIVERABLE_LOG.md`
  - `docs/evidence/`
- Master planning docs:
  - `docs/agenthub-master-plan-v1.2.docx`
  - `docs/agenthub-master-plan.docx`

## What This Repository Contains
AgentHub is organized as two connected layers:

- Agent DevHub (human-facing): registry, versioning, trust/evals, release review/promotion workflows, operator views.
- Agent Runtime Infrastructure (agent-native): capability discovery, delegation contracts, leases, procurement, marketplace, federation, billing, compliance, reliability controls.

## Implemented Platform Domains
| Domain | Primary Endpoints | Notes |
|---|---|---|
| Registry + Versioning | `POST /v1/agents`, `GET /v1/agents/{agent_id}/versions`, `GET /v1/agents/{agent_id}/compare/{base_version}/{target_version}` | Canonical manifest registration and behavioral diffing |
| Capability Search + Discovery | `POST /v1/capabilities/search`, `POST /v1/discovery/search`, `GET /v1/discovery/mcp-tools` | Policy-aware discovery, contract matching, MCP tool declaration export |
| Delegation Runtime | `POST /v1/delegations`, `GET /v1/delegations/{delegation_id}/status`, `GET /v1/delegations/contract` | Durable delegation contract with lifecycle/audit state |
| Lease + Install Control | `POST /v1/capabilities/lease`, `POST /v1/capabilities/leases/{lease_id}/promote`, `POST /v1/capabilities/installs/{install_id}/rollback` | Lease-first capability acquisition and promotion gates |
| Trust + Evals + Provenance | `GET /v1/agents/{agent_id}/trust`, `POST /v1/provenance/manifests/sign`, `POST /v1/provenance/artifacts/verify` | Trust scoring, tiered eval integration, signed provenance envelopes |
| Operator + DevHub | `GET /operator`, `GET /v1/operator/dashboard`, `POST /v1/devhub/reviews/{review_id}/promote` | Operator diagnostics UI and release collaboration lifecycle |
| Marketplace + Procurement + Billing | `POST /v1/marketplace/purchase`, `POST /v1/procurement/approvals`, `POST /v1/billing/invoices/generate` | Commercial flows with policy controls and reconciliation |
| Federation + Compliance + Reliability | `POST /v1/federation/execute`, `GET /v1/compliance/controls`, `GET /v1/reliability/slo-dashboard` | Domain federation, evidence export, SRE/SLO reporting |

## Architecture Principles
- Deterministic workflows first, autonomy only when measured lift is proven.
- Canonical internal contract with protocol adapters (MCP first, A2A second).
- Policy-first filtering before semantic ranking.
- Lease-first acquisition with explicit promotion checks.
- Strict cost guardrails, metering, and auditable actions.
- Idempotent write safety and replay-aware runtime semantics.
- Structured outputs and early schema validation.

See `AGENTS.md` and `docs/RESEARCH_INSIGHTS.md` for the full rationale and constraints.

## Prerequisites
- Python `>=3.11`
- `pip`
- Optional: Docker + Docker Compose

## Quick Start (Local API + UI)
```bash
cd /Users/demarioasquitt/Desktop/Projects/Entrepreneurial/agent-hub
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

Start API:
```bash
make dev
# or
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

Verify service:
```bash
curl -s http://127.0.0.1:8000/healthz
```

Open interfaces:
- OpenAPI UI: `http://127.0.0.1:8000/docs`
- OpenAPI JSON: `http://127.0.0.1:8000/openapi.json`
- Operator Console: `http://127.0.0.1:8000/operator`
- Version Compare UI: `http://127.0.0.1:8000/operator/versioning`
- Customer Journey Console: `http://127.0.0.1:8000/customer` (disabled by default; returns `404` unless enabled)

## Local Authentication Defaults
Default development API keys map to owners:

- `dev-owner-key` -> `owner-dev`
- `partner-owner-key` -> `owner-partner`
- `platform-owner-key` -> `owner-platform`

Use either:
- `X-API-Key` header, or
- Bearer token from `POST /v1/auth/tokens`

Example:
```bash
curl -s -X POST http://127.0.0.1:8000/v1/auth/tokens \
  -H "X-API-Key: dev-owner-key" \
  -H "Content-Type: application/json" \
  -d '{"scopes":["operator.refresh"],"ttl_seconds":1800}'
```

## Customer UI Hardening (S58)
- `GET /customer` returns `404` by default.
- Enable the route only for controlled demo/staging runs:
```bash
export AGENTHUB_CUSTOMER_UI_ENABLED=true
export AGENTHUB_CUSTOMER_UI_REQUIRE_AUTH=true
export AGENTHUB_CUSTOMER_UI_ALLOWED_OWNERS_JSON='["owner-dev","owner-platform"]'
```
- When enabled with auth required:
  - Missing auth -> `401`
  - Authenticated but owner not allowlisted -> `403`
- The page is a demo workflow surface, not production end-user auth UX.

## Idempotency + Access Enforcement
- Most write endpoints under `/v1/*` require `Idempotency-Key`.
- Access controls run in `enforce` mode by default.
- Set `AGENTHUB_ACCESS_ENFORCEMENT_MODE=warn` only for temporary migration compatibility.

## Startup Diagnostics (S61)
- Admin-only diagnostics endpoint:
  - `GET /v1/system/startup-diagnostics`
- Purpose:
  - Reports whether required startup security env vars are present/valid without exposing secret values.
- Access:
  - Allowed owners: `owner-dev`, `owner-platform`
  - Missing auth: `401`
  - Non-admin auth: `403`

## CLI Quick Start
Configure CLI:
```bash
agenthub login --api-url http://127.0.0.1:8000 --api-key dev-owner-key --json
agenthub whoami --json
agenthub doctor --local --json
agenthub doctor --remote --json
```

Create and validate a manifest:
```bash
agenthub init demo-agent --json
agenthub validate demo-agent/agent.yaml --json
```

Publish and search:
```bash
agenthub publish seed/agents/data-normalizer.yaml --namespace @seed --json
agenthub search "normalize records" --json
agenthub versions @seed:data-normalizer --json
```

## Testing
Run full test suite:
```bash
make test
# or
pytest -q
```

Useful targeted suites:
```bash
make operator-test
make versioning-test
make lease-test
make knowledge-test
make billing-test
make cli-test
```

Playwright E2E:
```bash
make e2e-install
make e2e-test
```

Strict hardening gate (same as CI required jobs):
```bash
pytest tests/auth/test_access_enforcement_s53.py tests/operator/test_operator_ui.py tests/gate/test_architecture_guardrails_s53.py -q
npm run e2e
```

Syntax/lint sanity:
```bash
make lint
```

## Docker Compose
Start local stack:
```bash
make compose-up
```

Stop:
```bash
make compose-down
```

Compose includes:
- API container (`8000`)
- Postgres (`5432`)
- Redis (`6379`)

## Useful Configuration Variables
- `AGENTHUB_ACCESS_ENFORCEMENT_MODE` (`warn` or `enforce`)
- `AGENTHUB_API_KEYS_JSON` (required JSON object of API key -> owner mappings)
- `AGENTHUB_AUTH_TOKEN_SECRET` (required bearer token signing secret)
- `AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON` (required JSON object of domain -> federation token)
- `AGENTHUB_PROVENANCE_SIGNING_SECRET` (required provenance signing secret)
- `AGENTHUB_CUSTOMER_UI_ENABLED` (`false` by default; controls `/customer` route availability)
- `AGENTHUB_CUSTOMER_UI_REQUIRE_AUTH` (`true` by default; auth requirement when customer UI is enabled)
- `AGENTHUB_CUSTOMER_UI_ALLOWED_OWNERS_JSON` (`["owner-dev","owner-platform"]` default owner allowlist for enabled customer UI)
- `AGENTHUB_OWNER_TENANTS_JSON` (owner-to-tenant mapping)
- `AGENTHUB_REGISTRY_DB_PATH` (registry SQLite path)
- `AGENTHUB_DELEGATION_DB_PATH` (delegation SQLite path)
- `AGENTHUB_BILLING_DB_PATH` (billing/metering SQLite path)
- `AGENTHUB_IDEMPOTENCY_DB_PATH` (idempotency reservation store)
- `AGENTHUB_HOME` (CLI config/state directory)

## Repository Layout
- `src/`: API and domain services (policy, delegation, billing, trust, discovery, federation, etc.)
- `agenthub/`: CLI package
- `tests/`: integration, domain, and operator/UI-adjacent tests
- `tools/`: evaluation, gate, launch, search, and trust utilities
- `specs/`: manifest and protocol contract artifacts
- `seed/`: seed manifests for local workflows
- `db/`: SQL schema and migrations
- `docs/`: strategy, segment packets, and evidence trail

## Key Documentation
- Segment tracker: `docs/DELIVERABLE_LOG.md`
- Evidence archive: `docs/evidence/`
- Research inputs: `docs/RESEARCH_INSIGHTS.md`
- Operator UX: `docs/operator/OPERATOR_UX_V2_S42.md`
- Policy plane: `docs/policy/POLICY_PLANE_V3.md`
- Delegation protocol: `docs/delegation/DELEGATION_PROTOCOL.md`
- Marketplace finance: `docs/billing/MARKETPLACE_FINANCE_V2_S44.md`
- Compliance controls: `docs/compliance/COMPLIANCE_CONTROLS_S47.md`
- GA rehearsal: `docs/launch/GA_REHEARSAL_RUNBOOK_S52.md`

## CI Required Checks (Branch Protection)
Workflow: `.github/workflows/quality-gates.yml`

Configure GitHub branch protection for `main`:
1. Enable `Require status checks to pass before merging`.
2. Add required checks:
   - `pytest-targeted`
   - `playwright-e2e`
   - `quality-gates`
   - In GitHub UI these may appear as:
     - `Quality Gates / pytest-targeted`
     - `Quality Gates / playwright-e2e`
     - `Quality Gates / quality-gates`
3. Keep these checks required for pull requests and direct pushes to protected branches.

## License
Proprietary/Confidential unless explicitly stated otherwise.
