# AgentHub — Claude Code Project Guide

## Autonomous Delivery Standard

These rules govern implementation, diagnosis, review, release, and handoff. More specific project invariants below remain binding.

### Scope and planning

- State assumptions, scope, and measurable success criteria before multi-step work.
- Turn the plan into `step -> verification` pairs and keep it current.
- Proceed autonomously with routine, reversible work inside the requested scope.
- Stop for missing credentials, destructive or production-wide actions, ownership conflicts, or choices that materially change the product.
- A request to diagnose, review, or report is read-only unless the user also authorizes changes.
- Inspect `git status -sb` first. Preserve unrelated tracked, untracked, staged, and generated work.

### Simplicity and adoption

- Write the minimum code that completely solves the requested problem.
- Search callers, registries, shared services, adapters, hooks, and existing implementations before adding a new abstraction or concern home.
- Extend the canonical layer when responsibility is the same. If a shared layer changes, migrate the touched callers rather than creating a sibling implementation.
- Do not add speculative configuration, redundant fallback paths, or infrastructure for remote hypotheticals.
- Update affected imports, exports, routers, task maps, migrations, schemas, clients, and documentation.
- Remove only dead code made obsolete by the current change. Do not clean unrelated debt.

### Outcome truth and no false greens

- A passing test, HTTP 200, status flag, database row, mock, screenshot, or healthy container is evidence, not proof of the claimed outcome.
- Verify the real producer, persistence, ownership boundary, consumer, and user or operator-visible result.
- For AgentHub, identity, capability discovery, policy, delegation or lease, revocation, provenance, billing, and operator state must be traced through the real owning modules and persisted stores; simulated control-plane behavior must not be described as real autonomous execution.
- Mocks and deterministic fixtures are acceptable development evidence only. Label them clearly and do not use them to support live-provider or production claims.
- Deployment proof requires exact repository, revision, artifact or image, configuration contract, health behavior, and rendered application identity.
- Never weaken a customer-facing claim to make QA pass. Fix the behavior or request an explicit positioning decision.

### Verification

- Bug fix: reproduce with a focused regression, implement the smallest fix, and prove the regression now passes.
- Start with the narrowest relevant checks, then run changed-file gates and broader build, integration, E2E, security, or release gates in proportion to risk.
- The normal AgentHub path is the narrowest pytest target, relevant Makefile lint/packaging/deployment gates, and Playwright or direct API proof when the operator or commercial flow changed.
- Test negative and adversarial cases for auth, isolation, validation, retries, partial failure, rollback, and cleanup when those boundaries change.
- Verify APIs with actual requests and response bodies, UI with a real render and interaction, persistence with stored and reloaded state, and background work with produced results and logs.
- If a required gate cannot run, report exactly what passed, what failed, and what remains unverified.

### Independent senior review

- Material production behavior, security boundaries, autonomous mutations, persistence, provider routing, migrations, deployment controls, and public UI changes require one separate independent xhigh review of an immutable base-to-head commit.
- Give the reviewer the full base and head SHAs, user requirements, affected architecture, tests, and runtime context. The reviewer is read-only and follows `.github/ai-review/senior-review.md`.
- HIGH or MEDIUM findings require a plausible current trigger, concrete impact, reproducible evidence, an affected file and line, and the smallest sufficient fix.
- Freeze the candidate on any admitted blocker. Fix narrowly, rerun relevant gates, commit a new head, and request one bounded re-review from the same reviewer.
- LOW, speculative, unrelated, stylistic, and non-reproducible observations do not extend the cycle.
- CI, previews, and deployment checks are separate evidence and do not replace independent review.

### Git, secrets, and production safety

- Stage and commit only files belonging to the current task. Use conventional, coherent commits without AI co-author trailers.
- Push once at the requested or final handoff boundary. Never force-push, rewrite history, or change remotes unless explicitly requested.
- Never print, log, screenshot, commit, or place secrets in command arguments. Source only required variables from an approved local or external secret store.
- Production starts read-only: verify target, identity, health, logs, rollback, and cleanup path before mutation.
- Never run destructive database, provider, deployment, or filesystem operations against an unresolved or broad target.
- Do not claim deployment, rollback, cleanup, or public verification that was not directly observed.

### Commit cadence and pull-request lifecycle

- One branch and one pull request represent one coherent customer-impact or operational slice. Start material work from the latest verified default branch on `codex/<short-slug>` unless the task already owns a suitable branch.
- Commit each verified, bisectable checkpoint and at least once at the end of a successful work session. Do not wait for a large dump, create noisy save-point commits, or mix unrelated cleanup.
- Every commit must preserve focused green evidence for its changed property. Use conventional messages, stage only task-owned files, and never add AI co-author trailers.
- Batch local commits and push once at the authorized session or correction-cycle boundary. Do not push after every commit, force-push, amend, rebase, or otherwise rewrite a candidate that has been shared or reviewed.
- At the first authorized push for a material slice, open or update one draft pull request; never create a duplicate PR for the same branch. Documentation that accompanies code stays in that PR. Do not create a PR solely for low-risk documentation unless repository protection requires it.
- Keep the PR draft while required tests, preview or runtime proof, rollback planning, cleanup, or independent exact-commit review remains incomplete. Record exact base, head, and tree SHAs plus the commands and results that support the candidate.
- Freeze the PR head for independent review. HIGH or MEDIUM findings keep it blocked and draft; make the smallest coherent fix as a new commit, push once, freeze the new head, rerun affected gates, and request bounded re-review.
- Mark ready and merge only when the current remote head is the reviewed head, required evidence is green, conversations are resolved, and the task includes merge or release authority. Use a merge commit, not squash or rebase, so candidate commits and review identities remain recoverable.
- An accepted PR is merged and GitHub closes it automatically. Manually close only an abandoned, duplicate, or explicitly superseded PR, and leave a final comment naming the reason, preserved head SHA, remaining blockers, and successor when one exists. Never close a PR to hide a blocker.
- After merge, record the PR number and merge SHA, verify the merged tree and any required deployment or public behavior, then report rollback and cleanup state. Delete a branch or worktree only when it is merged or superseded, clean, idle, and explicitly released; otherwise preserve it.

### Handoff

Report the exact branch and head, files changed, tests and probes run, runtime or public evidence, independent-review result, rollback and cleanup state, and remaining risks. Distinguish complete, partial, blocked, and unverified work explicitly.

### AgentHub risk focus

Prioritize OAuth wildcard authority, scope attenuation, revocation-aware verification, policy signing, object authorization, replay safety, and tenant ownership.

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
- **Testing**: pytest with focused-first scope, Playwright for E2E, and broader suites at release boundaries
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
| Identity | `src/identity/` | Agent IAM: credentials, delegation tokens, revocation, federation |
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
| `AGENTHUB_POLICY_SIGNING_SECRET` | Yes | Policy decision signing and verification |
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

Use repository test fixtures or locally supplied development secrets. Never copy development credentials into production configuration or evidence.

## Segment Workflow
1. Create `docs/session-packets/Sxx.md`
2. Implement changes
3. Run targeted tests (`pytest tests/specific_test.py -v`)
4. Write evidence to `docs/evidence/Sxx.md`
5. Update `docs/DELIVERABLE_LOG.md`
6. Commit the coherent segment; push once at the requested or final handoff boundary

## Verification (Pre-Commit)
1. `pyright` on modified files
2. Pre-commit hooks (automatic)
3. Functional: `curl` endpoints, check responses
4. Run broader suites only when the affected surface or release boundary justifies them; record known baseline failures separately

## File Placement Rules (MANDATORY)

| File Type | Location |
|-----------|----------|
| API route | `src/api/routes/` |
| Middleware | `src/api/middleware/` |
| Identity logic | `src/identity/` |
| Policy logic | `src/policy/` |
| Delegation logic | `src/delegation/` |
| Federation logic | `src/federation/` |
| Type definitions | `*/types.py` within each module |
| Constants | `*/constants.py` within each module |
| Storage/CRUD | `*/storage.py` within each module |

### Before Creating Any New File
1. Check if a module subdirectory exists — use it
2. Don't scatter related files — colocate by module
3. If moving files, update all imports and `__init__.py` re-exports

## Dead Code & Orphan Prevention (MANDATORY)

### When Your Changes Create Orphans — Clean Up Immediately
When your changes make files, imports, or functions unused, **delete them in the same commit**:
- You replaced `ServiceA` with `ServiceB` → delete `ServiceA`
- You moved logic from `old_module.py` → delete `old_module.py`
- You stopped importing a function → remove it from `__init__.py`

### When Moving or Refactoring Files
1. Grep for old import path before deleting/moving
2. Update `__init__.py` re-exports
3. Run pyright to verify no broken references

## NEVER Mark Tasks Complete Without Verification (CRITICAL)

**NEVER claim something is working or mark a task complete without ACTUALLY verifying it.**

### Verification Requirements
1. **API responses**: curl the endpoint, check the response
2. **Identity operations**: Verify credential creation, delegation, revocation
3. **Policy decisions**: Test with sample policy evaluations
4. **Type checks**: pyright passes on modified files

### When Verification Fails
1. Diagnose the root cause
2. Fix the underlying issue
3. Re-run and verify again
4. Only then report success

**If you cannot verify, say so explicitly. Never fabricate verification results.**

## Workflow Conventions (MANDATORY)

### Immediate Execution, Not Summarization
When implementing from a plan document, start execution immediately. Do NOT summarize the plan.

### Scope Discipline
Implement exactly what's requested before expanding. Do NOT over-scope.

### Debugging Structure
Start from the error traceback → trace the call chain → identify root cause → then fix.

## Mandatory Architectural Review (BEFORE IMPLEMENTATION)

When a task involves creating 2+ new files or modifying 3+ existing files:
1. **File Size**: Will any file exceed 800 lines?
2. **Single Responsibility**: Does each file have ONE clear purpose?
3. **Module Boundaries**: Is this in the right module?
4. **Security**: Does this maintain scope attenuation, fail-closed auth?

Use subagents only for genuinely independent work or when the user or applicable instructions request parallelism.

## Git
- Conventional commits: `feat:`, `fix:`, `refactor:`, etc.
- Never add Co-Authored-By lines
- Commit coherent changes; push once at the requested or final handoff boundary
