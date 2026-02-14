# AgentHub — Claude Code Project Guide

## Mission
Build AgentHub as the IAM layer for autonomous systems — the "Okta for agents." Provides agent identity, credential lifecycle, delegated authority, revocable permissions, and cross-org federation on top of an existing registry, delegation, policy, and marketplace platform.

## Strategic Context
- Wealth Play #1 from the Agentic AI Strategic Playbook (Feb 2026)
- Competitive landscape: Cyata ($8.5M seed), Strata Identity, Aembit ($25M Series A) — no dominant player
- Standards forming: AAP (IETF), MCP auth, A2A protocol, SPIFFE
- 12-18 month window before market consolidation

## Tech Stack
- **Language**: Python 3.11+
- **Framework**: FastAPI
- **Persistence**: SQLite (WAL mode) for runtime stores, PostgreSQL 16 + pgvector for production schema
- **Auth**: HMAC-SHA256 signed tokens, API key mapping, scoped bearer tokens
- **Testing**: pytest (targeted only — never run full suite), Playwright for E2E
- **CI**: GitHub Actions (`quality-gates.yml`)

## Module Map

| Module | Path | Responsibility |
|--------|------|---------------|
| API | `src/api/` | FastAPI app, routes, auth, models, access policy, middleware |
| Registry | `src/registry/` | Agent catalog, versioning, namespace ownership |
| Delegation | `src/delegation/` | 6-stage lifecycle, budget escrow, idempotency |
| Policy | `src/policy/` | ABAC engine, signed decisions, explainability |
| Discovery | `src/discovery/` | Capability search, indexing, contract matching |
| Federation | `src/federation/` | Cross-domain execution, attestation, data residency |
| Lease | `src/lease/` | Capability acquisition with TTL, promotion gates |
| Trust | `src/trust/` | Reputation scoring |
| Identity | `src/identity/` | **NEW** Agent IAM: credentials, delegation tokens, revocation, federation |
| Billing | `src/billing/` | Metering, invoicing, reconciliation |
| Marketplace | `src/marketplace/` | Commercial transactions, disputes, payouts |
| Compliance | `src/compliance/` | SOC2/ISO controls, evidence export |
| Provenance | `src/provenance/` | Artifact signing, manifest verification |
| Reliability | `src/reliability/` | SRE/SLO controls, circuit breakers |

## Architecture Decisions
1. Deterministic workflows first, autonomy only with measured lift
2. Canonical internal contract + protocol adapters (MCP first, A2A second)
3. Policy-first capability discovery (enforce before rank)
4. Lease-first capability acquisition (temporary by default)
5. Cost guardrails: 80% soft alert, 100% re-auth, 120% hard stop
6. Tool-call reliability and idempotency (all writes need idempotency keys)
7. Structured outputs by default (strict schema validation)
8. **Agent identity as first-class primitive** (not user extensions)
9. **Scope attenuation in delegation chains** (permissions only reduce, never add)
10. **Real-time revocation** (kill switch within 1 second, no caching)

## Security Baseline
1. Treat all tool inputs/outputs as untrusted
2. Sandbox delegated execution
3. Enforce least privilege for tool access and secrets
4. Use scoped, short-lived credentials (max 30 days)
5. Add explicit high-risk action approvals
6. Log all privileged actions with actor, tool, input hash, output hash, cost, timestamp
7. Fail-closed on all auth decisions
8. Cascade revocation: revoking a credential revokes all downstream tokens

## Identity Module (`src/identity/`)

### Files
- `types.py` — TypedDicts: AgentIdentity, AgentCredential, DelegationToken, RevocationEvent
- `constants.py` — Credential types, TTL defaults (max 30 days), max chain depth (5), algorithms
- `storage.py` — SQLite schema + CRUD (follows `delegation/storage.py` pattern)
- `credentials.py` — Issue, rotate, verify, revoke (reuses HMAC from `api/auth.py`)
- `delegation_tokens.py` — Issue, verify, decode with scope attenuation
- `chain.py` — Chain validation, depth checking, scope intersection
- `revocation.py` — Revoke, cascade, bulk operations
- `federation.py` — Trust registry, agent identity attestation

### Key Invariants
- All credentials have expiry (max 30 days)
- Delegation tokens MUST attenuate scopes (child subset of parent)
- Chain depth limited to 5
- Revocation takes effect within 1 second
- Credentials stored as HMAC-SHA256 hashes (never plaintext)

### Integration Points
- `src/api/auth.py` — Authentication resolver uses agent credentials + delegation tokens
- `src/policy/runtime.py` — Policy engine validates credential issuance and delegation
- `src/delegation/service.py` — Accepts delegation tokens, records chains
- `src/federation/gateway.py` — Verifies agent identity for cross-domain calls
- `src/lease/service.py` — Binds leases to credential lifecycle

## Environment Variables
| Variable | Required | Description |
|----------|----------|-------------|
| `AGENTHUB_API_KEYS_JSON` | Yes | JSON: API key → owner mapping |
| `AGENTHUB_AUTH_TOKEN_SECRET` | Yes | Bearer token signing secret |
| `AGENTHUB_IDENTITY_SIGNING_SECRET` | Yes | Agent credential + delegation token signing |
| `AGENTHUB_IDENTITY_DB_PATH` | No | Identity SQLite path (default: `data/identity.db`) |
| `AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON` | Yes | Domain → federation token mapping |
| `AGENTHUB_PROVENANCE_SIGNING_SECRET` | Yes | Provenance envelope signing |
| `AGENTHUB_ACCESS_ENFORCEMENT_MODE` | No | `enforce` (default) or `warn` |
| `AGENTHUB_OWNER_TENANTS_JSON` | No | Owner → tenant mapping |

## Local Dev
```bash
cd /Users/demarioasquitt/Desktop/Projects/Entrepreneurial/agent-hub
source .venv/bin/activate
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

Default API keys: `dev-owner-key` → `owner-dev`, `partner-owner-key` → `owner-partner`, `platform-owner-key` → `owner-platform`

## Segment Workflow
1. Create `docs/session-packets/Sxx.md`
2. Implement changes
3. Run targeted tests (`pytest tests/specific_test.py -v`)
4. Write evidence to `docs/evidence/Sxx.md`
5. Update `docs/DELIVERABLE_LOG.md`
6. Commit and push

## Verification (Pre-Commit)
1. `pyright` on modified files
2. Pre-commit hooks (automatic)
3. Functional: `curl` endpoints, check responses
4. **Never run full test suite** — wastes API credits

## Git
- Conventional commits: `feat:`, `fix:`, `refactor:`, etc.
- Never add Co-Authored-By lines
- Commit and push after all code changes
