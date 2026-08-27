# AgentHub

AgentHub is a local control-plane prototype for agent identity, delegated authority, capability discovery, revocation, and policy research. It is not production-ready and does not yet execute remote agent workloads.

## Current Status
- The repository contains many historical segments, but segment completion is not equivalent to production or customer readiness.
- S163-S165 provide the current evidence-backed baseline: P0 containment, an authenticated inbound MCP discovery endpoint, and durable local identity authority.
- Identity, revocation, and discovery behavior is proven only in the documented local single-process SQLite boundary.
- Runtime, delegation, federation execution, webhook delivery, and customer journeys remain simulators or control-plane state machines; they do not prove external execution.
- Billing, marketplace settlement, procurement charging, and synthetic delegation charging are disabled by default pending transactional-integrity proof.
- Hosted CI, public deployment, multi-replica safety, production migrations, real customer outcomes, and a governed remote tool invocation are not proven.
- Source of truth for delivery status and evidence:
  - `docs/DELIVERABLE_LOG.md`
  - `docs/evidence/`
- Master planning docs:
  - `docs/agenthub-master-plan-v1.2.docx`
  - `docs/agenthub-master-plan.docx`

## What This Repository Contains
AgentHub is organized as two connected layers:

- Agent DevHub (human-facing): registry, versioning, trust/evals, release review/promotion workflows, operator views.
- Agent Runtime Infrastructure (agent-native): capability discovery plus prototype contracts and policy primitives. Real governed remote invocation remains unfinished.

## Implemented Platform Domains
| Domain | Primary Endpoints | Notes |
|---|---|---|
| Marketing Site | `GET /` | Public-facing value proposition, product positioning, and primary CTA navigation |
| Registry + Versioning | `POST /v1/agents`, `GET /v1/agents/{agent_id}/versions`, `GET /v1/agents/{agent_id}/compare/{base_version}/{target_version}` | Canonical manifest registration and behavioral diffing |
| Capability Search + Discovery | `POST /v1/capabilities/search`, `POST /v1/discovery/search`, `POST /mcp` | Policy-aware discovery plus an authenticated MCP Streamable HTTP gateway backed by the canonical discovery service |
| Delegation Simulator | `POST /v1/delegations`, `GET /v1/delegations/{delegation_id}/status`, `GET /v1/delegations/contract` | Development-only synthetic lifecycle; disabled by default because no delegate is invoked |
| Lease + Install Control | `POST /v1/capabilities/lease`, `POST /v1/capabilities/leases/{lease_id}/promote`, `POST /v1/capabilities/installs/{install_id}/rollback` | Lease-first capability acquisition and promotion gates |
| Trust + Evals + Provenance | `GET /v1/agents/{agent_id}/trust`, `POST /v1/provenance/manifests/sign`, `POST /v1/provenance/artifacts/verify` | Trust scoring, tiered eval integration, signed provenance envelopes |
| Operator + DevHub | `GET /operator`, `GET /v1/operator/dashboard`, `GET /v1/operator/startup-diagnostics`, `GET /v1/operator/startup-diagnostics/history`, `POST /v1/devhub/reviews/{review_id}/promote` | Operator diagnostics UI, startup readiness diagnostics, and release collaboration lifecycle |
| Marketplace + Procurement + Billing | `POST /v1/marketplace/purchase`, `POST /v1/procurement/approvals`, `POST /v1/billing/invoices/generate` | Prototype commercial records; financial mutations are disabled by default |
| Federation + Compliance + Reliability | `POST /v1/federation/execute`, `GET /v1/compliance/controls`, `GET /v1/reliability/slo-dashboard` | Local federation simulation, evidence export, and SRE/SLO primitives |
| Agent Identity & Credentials | `POST /v1/identity/agents`, `POST /v1/identity/agents/{id}/credentials`, `POST /v1/identity/credentials/{id}/rotate`, `POST /v1/identity/credentials/{id}/revoke` | Agent identity registration, scoped credential issuance, rotation, and revocation |
| Delegation Tokens & Chains | `POST /v1/identity/delegation-tokens`, `POST /v1/identity/delegation-tokens/verify`, `GET /v1/identity/delegation-tokens/{id}/chain` | Scope-attenuated delegation tokens with multi-hop chain validation (max depth 5) |
| Revocation & Kill Switch | `POST /v1/identity/agents/{id}/revoke`, `POST /v1/identity/revocations/bulk`, `GET /v1/identity/revocations` | Instant agent kill switch with cascade to credentials, tokens, and leases |
| Trust Registry & Federation | `POST /v1/identity/trust-registry/domains`, `POST /v1/identity/agents/{id}/attest`, `GET /v1/identity/attestations/{id}/verify` | Cross-org trust registry, signed agent attestations, federated identity verification |
| Runtime State Simulator | `POST /v1/runtime/sandboxes`, `POST /v1/runtime/sandboxes/{id}/execute`, `POST /v1/runtime/sandboxes/{id}/complete`, `POST /v1/runtime/sandboxes/{id}/terminate` | Local lifecycle records only; no OS isolation or workload execution |
| Runtime Integration Simulator | `POST /v1/runtime/sandboxes/delegated`, `POST /v1/runtime/sandboxes/leased`, `GET /v1/runtime/audit/evidence` | Development records for delegation/lease integration, not execution evidence |

## Architecture Principles
- Deterministic workflows first, autonomy only when measured lift is proven.
- Canonical internal contract with protocol adapters (MCP first, A2A second).
- Policy-first filtering before semantic ranking.
- Lease-first acquisition with explicit promotion checks.
- Cost-policy prototypes and metering records; financial integrity remains unfinished.
- Idempotent write safety and replay-aware runtime semantics.
- Structured outputs and early schema validation.
- Credential-based identity with scope attenuation — child scopes must be subset of parent.
- Revocation-aware local identity artifacts with documented boundary limitations.

See `docs/RESEARCH_INSIGHTS.md` for the full rationale and constraints.

## Prerequisites
- Python `>=3.11`
- `pip`
- Optional: Docker + Docker Compose

## Quick Start (Local API + UI)
```bash
git clone https://github.com/asquitt/agent-hub.git
cd agent-hub
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

## MCP Discovery Gateway
AgentHub exposes a stateless MCP Streamable HTTP endpoint at `POST /mcp`. It implements the `2025-11-25` initialization lifecycle and serves three read-only tools backed by the same policy and tenant-aware services as the REST API:

- `search_capabilities`
- `get_agent_manifest`
- `check_compatibility`

OAuth clients should request a resource-bound access token by sending `resource=<AGENTHUB_BASE_URL>/mcp` to `POST /v1/oauth/token`. AgentHub places that exact resource in the token `aud` claim, verifies it at `/mcp`, and rejects replay of the audience-bound token against generic REST endpoints. Protected Resource Metadata is available at `GET /.well-known/oauth-protected-resource`.

This surface currently supports API-key authentication and OAuth `client_credentials`. It does not claim authorization-code, PKCE, browser login, SSE session resumption, or managed remote execution.

Run the official SDK interoperability gate in an isolated client environment so its dependency versions do not replace AgentHub runtime pins:

```bash
python -m venv .venv-mcp-client
.venv-mcp-client/bin/python -m pip install -r requirements-mcp-test.txt
AGENTHUB_OFFICIAL_MCP_PYTHON="$PWD/.venv-mcp-client/bin/python" \
  python -m pytest -q tests/protocol/test_mcp_official_sdk_s164.py
```

## Agent Identity Authentication (S72-S78)
AgentHub supports three authentication methods, checked in order:

1. **Platform API Key** (`X-API-Key` header) — full access, maps to owner.
2. **Agent Credential** (`Authorization: AgentCredential <secret>`) — scoped access tied to an agent identity.
3. **Delegation Token** (`X-Delegation-Token` header) — scoped, time-limited delegated access from one agent to another.

Register an agent and issue credentials:
```bash
# Register agent identity
curl -s -X POST http://127.0.0.1:8000/v1/identity/agents \
  -H "X-API-Key: dev-owner-key" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "my-agent", "credential_type": "api_key"}'

# Issue scoped credential (returns secret — store securely)
curl -s -X POST http://127.0.0.1:8000/v1/identity/agents/my-agent/credentials \
  -H "X-API-Key: dev-owner-key" \
  -H "Content-Type: application/json" \
  -d '{"scopes": ["read", "execute"], "ttl_seconds": 86400}'

# Authenticate as agent
curl -s http://127.0.0.1:8000/v1/identity/agents/my-agent \
  -H "Authorization: AgentCredential <secret-from-above>"
```

Issue delegation tokens with scope attenuation:
```bash
# Agent A delegates "read" scope to Agent B
curl -s -X POST http://127.0.0.1:8000/v1/identity/delegation-tokens \
  -H "X-API-Key: dev-owner-key" \
  -H "Content-Type: application/json" \
  -d '{"issuer_agent_id": "agent-a", "subject_agent_id": "agent-b", "delegated_scopes": ["read"], "ttl_seconds": 3600}'
```

Kill switch — instantly revoke an agent and cascade to all credentials, tokens, and leases:
```bash
curl -s -X POST http://127.0.0.1:8000/v1/identity/agents/my-agent/revoke \
  -H "X-API-Key: dev-owner-key" \
  -H "Content-Type: application/json" \
  -d '{"reason": "security_incident"}'
```

## Runtime State Simulator (S79-S82)
These endpoints persist a development lifecycle state machine. The in-process driver does not execute the submitted workload, gVisor and Firecracker drivers are not implemented, and completion output is caller supplied. Do not use these records as execution, isolation, metering, or customer-outcome evidence.

Provision a sandbox and run an execution:
```bash
# Create sandbox with micro profile (0.25 CPU, 256MB, 30s timeout, network disabled)
curl -s -X POST http://127.0.0.1:8000/v1/runtime/sandboxes \
  -H "X-API-Key: dev-owner-key" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "my-agent", "profile_name": "micro"}'

# Start execution in sandbox
curl -s -X POST http://127.0.0.1:8000/v1/runtime/sandboxes/{sandbox_id}/execute \
  -H "X-API-Key: dev-owner-key" \
  -H "Content-Type: application/json" \
  -d '{"input_data": {"task": "analyze", "params": {"x": 1}}}'

# Complete execution
curl -s -X POST http://127.0.0.1:8000/v1/runtime/sandboxes/{sandbox_id}/complete \
  -H "X-API-Key: dev-owner-key" \
  -H "Content-Type: application/json" \
  -d '{"exit_code": 0, "output_data": {"result": "done"}}'
```

Resource profiles (micro/small/medium/large) are seeded automatically. Create custom profiles:
```bash
curl -s -X POST http://127.0.0.1:8000/v1/runtime/profiles \
  -H "X-API-Key: dev-owner-key" \
  -H "Content-Type: application/json" \
  -d '{"name": "gpu-heavy", "cpu_cores": 2.0, "memory_mb": 4096, "timeout_seconds": 600, "network_mode": "egress_only", "disk_io_mb": 1024}'
```

Delegation-linked sandbox (auto-created during delegation, also available via API):
```bash
curl -s -X POST http://127.0.0.1:8000/v1/runtime/sandboxes/delegated \
  -H "X-API-Key: dev-owner-key" \
  -H "Content-Type: application/json" \
  -d '{"delegation_id": "<delegation-id>", "agent_id": "delegate-agent"}'
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
  - Includes path probes and `overall_ready` (startup checks + probe checks).
  - Includes severity metadata and summary counters for rapid triage.
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

Compose includes one API container (`8000`) and one local data volume. The API uses SQLite and rejects declared multi-worker or multi-replica topology. Postgres and Redis are not connected or included.

## Useful Configuration Variables
- `AGENTHUB_ACCESS_ENFORCEMENT_MODE` (`warn` or `enforce`)
- `AGENTHUB_API_WORKERS` and `AGENTHUB_API_REPLICAS` (must both remain `1` while SQLite owns state)
- `AGENTHUB_SINGLETON_LOCK_PATH` (process-ownership lock for the local SQLite deployment)
- `AGENTHUB_ENABLE_UNSAFE_FINANCIAL_MUTATIONS` (development-only opt-in; disabled by default)
- `AGENTHUB_CORS_ORIGINS` (comma-separated allowed origins; defaults to `*`)
- `AGENTHUB_RATE_LIMIT_DEFAULT` (rate limit per API key; defaults to `100/minute`)
- `AGENTHUB_REQUEST_TIMEOUT_SECONDS` (HTTP request timeout; defaults to `30`)
- `AGENTHUB_LOG_LEVEL` (logging level; defaults to `INFO`)
- `AGENTHUB_API_KEYS_JSON` (required JSON object of API key -> owner mappings)
- `AGENTHUB_AUTH_TOKEN_SECRET` (required bearer token signing secret)
- `AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON` (required JSON object of domain -> federation token)
- `AGENTHUB_PROVENANCE_SIGNING_SECRET` (required provenance signing secret)
- `AGENTHUB_CUSTOMER_UI_ENABLED` (`false` by default; controls `/customer` route availability)
- `AGENTHUB_CUSTOMER_UI_REQUIRE_AUTH` (`true` by default; auth requirement when customer UI is enabled)
- `AGENTHUB_CUSTOMER_UI_ALLOWED_OWNERS_JSON` (`["owner-dev","owner-platform"]` default owner allowlist for enabled customer UI)
- `AGENTHUB_OWNER_TENANTS_JSON` (owner-to-tenant mapping)
- `AGENTHUB_BASE_URL` (canonical public origin used for MCP resource and OAuth metadata URLs)
- `AGENTHUB_MCP_ALLOWED_ORIGINS_JSON` (additional browser origins allowed to call `/mcp`)
- `AGENTHUB_IDENTITY_SIGNING_SECRET` (required for agent credential and delegation token signing)
- `AGENTHUB_IDENTITY_DB_PATH` (identity SQLite path; defaults to `data/identity/identity.db`)
- `AGENTHUB_REGISTRY_DB_PATH` (registry SQLite path)
- `AGENTHUB_DELEGATION_DB_PATH` (delegation SQLite path)
- `AGENTHUB_BILLING_DB_PATH` (billing/metering SQLite path)
- `AGENTHUB_IDEMPOTENCY_DB_PATH` (idempotency reservation store)
- `AGENTHUB_RUNTIME_DB_PATH` (runtime/sandbox SQLite path; defaults to `data/runtime/runtime.db`)
- `AGENTHUB_HOME` (CLI config/state directory)

## Repository Layout
- `src/`: API and domain services (policy, delegation, billing, trust, discovery, federation, identity, etc.)
- `src/identity/`: Agent identity module — credentials, delegation tokens, revocation, federation trust registry
- `src/api/routes/identity.py`: Identity API endpoints (17 endpoints under `/v1/identity/*`)
- `src/runtime/`: Development runtime state simulator, policy prototypes, metering records, and audit helpers
- `src/api/routes/runtime.py`: Runtime API endpoints (16 endpoints under `/v1/runtime/*`)
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

## CI Execution (Temporarily Manual)
Workflow: `.github/workflows/quality-gates.yml`

Automatic `push` and `pull_request` triggers are disabled while GitHub Actions billing is blocked. Run the preserved workflow manually with `workflow_dispatch` when hosted execution is available. This is not a hosted green gate.

After billing is restored, re-enable automatic pull-request triggers and configure branch protection for `main`:
1. Enable `Require status checks to pass before merging`.
2. Add required checks:
   - `pytest-full`
   - `playwright-e2e`
   - `quality-gates`
   - In GitHub UI these may appear as:
     - `Quality Gates / pytest-full`
     - `Quality Gates / playwright-e2e`
     - `Quality Gates / quality-gates`
3. Keep these checks required for pull requests and direct pushes to protected branches.

## License
Proprietary/Confidential unless explicitly stated otherwise.
