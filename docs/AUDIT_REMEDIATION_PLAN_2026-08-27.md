# AgentHub Audit Remediation Plan

## Current Verdict

**NO-GO for production or customer pilots.** The merged `main` baseline at `0b7d1889a91a43a20f3e10f026172839d77e09cb` is materially safer than the February audit target, but it remains a single-process local control-plane prototype. The current S167 candidate adds one real operator-attested, server-declared read-only/idempotent, auth-none MCP call with fresh revocation-aware admission and Ed25519 receipts. General remote workloads, upstream authentication, write tools, webhook delivery, distributed persistence, production deployment, and customer outcomes are not proven.

The current S167 local candidate is `854 passed, 1 skipped`; its official MCP server process tests run in the exact application runtime dependency environment. This is repository evidence only, not hosted CI, deployment, provider, or customer evidence.

## Status Definitions

- `COMPLETE_LOCAL`: exit criterion is proven locally within an explicit boundary.
- `PARTIAL`: reusable implementation exists, but the exit criterion is not met.
- `IN_PROGRESS`: the current candidate is implementing or verifying the exit criterion.
- `UNSTARTED`: no implementation satisfies the exit criterion.
- `DEFERRED`: intentionally blocked behind pilot gates.

## P0A: Containment And Truth

| ID | Status | Current disposition |
|---|---|---|
| AH-001 | IN_PROGRESS | Freeze remains the default; S167 is the only approved new product path because it replaces a simulator with the required real invocation boundary. |
| AH-002 | COMPLETE_LOCAL | S166 labels every OpenAPI operation `prototype`, `stub`, or `deferred`; S167 preserves the boundary for all 448 operations. |
| AH-003 | COMPLETE_LOCAL | README, marketing, runtime, webhook, OpenAPI, and ledger claims match the documented local evidence boundary. |
| AH-004 | PARTIAL | Full local suite is green; automatic required hosted CI remains intentionally disabled and unproven. |
| AH-005 | PARTIAL | Strict local dependency audits have passed; no provider-enforced blocking gate is proven. |
| AH-006 | COMPLETE_LOCAL | Typed auth context preserves owner, tenant, scopes, roles, auth method, agent, and delegation metadata. |
| AH-007 | IN_PROGRESS | Identity/vault boundaries are repaired; S166 closes reproduced cross-owner delegation status. Comprehensive object authorization remains a continuing gate. |
| AH-008 | COMPLETE_LOCAL | OAuth client grants are durable and requested scopes are attenuated to registered authority. |
| AH-009 | COMPLETE_LOCAL | Declared topology rejection and the singleton process lock contain SQLite to one local process. |
| AH-010 | COMPLETE_LOCAL | Unsafe billing, marketplace, procurement, and delegated charging are disabled before mutation by default. |
| AH-011 | COMPLETE_LOCAL | Rate limit, timeout, readiness, and delegation breaker behavior is locally tested. |
| AH-012 | PARTIAL | Wheel packaging is repaired; exact-image clean build/boot/readiness proof remains. |
| AH-013 | IN_PROGRESS | S163-S166 use exact evidence; S166 removes unsupported `DONE` status from undocumented S72-S90 rows. |

## P0B: Functional Product Core

| ID | Status | Current disposition |
|---|---|---|
| AH-014 | PARTIAL | PostgreSQL schema artifact exists; application state remains split across SQLite stores. |
| AH-015 | UNSTARTED | No Redis coordination, distributed counters, locks, or invalidation. |
| AH-016 | PARTIAL | SQLite migration ledger exists; no Alembic checksums, advisory lock, deployment job, or rollback proof. |
| AH-017 | UNSTARTED | No transactional outbox around calls, webhooks, audit export, or state transitions. |
| AH-018 | COMPLETE_LOCAL | Authenticated inbound MCP discovery and the official MCP SDK outbound client are locally proven for the bounded relay. |
| AH-019 | PARTIAL | Signed attenuation and durable roots exist; public schema, asymmetric verifier, and test vectors remain. |
| AH-020 | COMPLETE_LOCAL | The bounded relay repeats principal, capability, target, and policy checks under one local authority fence immediately before dispatch. |
| AH-021 | COMPLETE_LOCAL | One exact operator-attested, server-declared read-only/idempotent auth-none MCP tool is invoked through the production client; technical prevention of upstream side effects is not claimed. |
| AH-022 | COMPLETE_LOCAL | Relay outcomes receive Ed25519 action receipts with a public JWK and offline verifier; broader action types remain outside this slice. |
| AH-023 | COMPLETE_LOCAL | Capability revocation is durable and the next governed relay attempt is denied before network dispatch. |
| AH-024 | UNSTARTED | No OpenTelemetry traces, metrics, propagation, or receipt correlation. |
| AH-025 | PARTIAL | Subscription-shaped APIs exist; S166 stops false delivery claims. HTTP delivery, retry, and durable DLQ remain. |
| AH-026 | PARTIAL | Local registry and fixture catalog exist; no official/private ingestion or package/SBOM/signature binding. |
| AH-027 | PARTIAL | Local malformed input/output, restart, remote MCP process, and crash-ambiguity tests exist; no two-replica or distributed-failure suite. |
| AH-028 | COMPLETE_LOCAL | API proof imports, budgets, invokes, verifies a receipt, revokes, and denies the next attempt against a separate MCP process. |

## P1: Customer Product

| ID | Status | Current disposition |
|---|---|---|
| AH-029 | UNSTARTED | No human login, organizations, workspaces, or customer sessions. |
| AH-030 | PARTIAL | Registry data exists; no consolidated source/runtime/permission/health/evidence inventory. |
| AH-031 | PARTIAL | Operator environment configuration and remote tool import exist for one exact auth-none target; customer URL/OAuth/credential onboarding does not. |
| AH-032 | PARTIAL | Policy APIs exist; no unified visual builder bound to a real invocation. |
| AH-033 | PARTIAL | In-memory approvals exist; no durable inbox or real-call pause/resume. |
| AH-034 | PARTIAL | Provenance and audit primitives exist; no action receipt explorer or portable verifier. |
| AH-035 | PARTIAL | Identity revocation and chain analysis exist; no incident workflow or complete blast radius. |
| AH-036 | PARTIAL | Metering/SLO primitives exist, but source data is synthetic or manually posted. |
| AH-037 | PARTIAL | Python identity client exists; TypeScript SDK, relay middleware, receipt verifier, and correct examples remain. |
| AH-038 | PARTIAL | Local README/API guidance exists; no connect-policy-invoke-receipt-revoke quickstart or production guide. |
| AH-039 | PARTIAL | A2A cards/mappings exist; task transport, streaming, cancellation, subscriptions, auth, and negotiation remain. |
| AH-040 | UNSTARTED | No customer-hosted enforcement sidecar or outbound proxy. |
| AH-041 | PARTIAL | SCIM/federation/webhook-shaped APIs exist; no verified IdP, SIEM, GRC, OPA, or cloud connector. |
| AH-042 | PARTIAL | Local Docker/Compose containment exists; IaC, secrets, restore, rollback, SBOM, signed image, and deployment proof remain. |
| AH-043 | UNSTARTED | No design-partner-native activation, first-call, risk-denial, success, or ROI telemetry. |
| AH-044 | PARTIAL | Marketing now names the bounded governed relay from local proof; customer evidence and acquisition validation remain absent. |
| AH-045 | PARTIAL | Responsive demo pages exist; customer information architecture, shared design system, accessibility semantics, and real data states remain. |

## P2: Gate-Deferred Expansion

AH-046 exact-version assurance exchange, AH-047 evidence-backed reputation, AH-048 autonomous procurement, AH-049 marketplace, AH-050 managed runtime, AH-051 shared knowledge artifacts, and AH-052 advanced identity formats are `DEFERRED` until all of the following are measured on real governed calls:

1. Reliability target is met in pilot workloads.
2. Design partners show positive operational ROI.
3. Unit economics remain sustainable under real multi-agent load.
4. Revocation, receipts, approvals, and incident response work end to end.

## Execution Order

1. **S166, containment:** finish AH-002, AH-003, the reproduced AH-007 gap, AH-009, AH-010, and AH-013.
2. **S167, governed MCP relay v0:** local implementation and verification complete; exact-candidate image/review/merge evidence remains before the segment closes.
3. **Shared data authority:** AH-014-AH-017 with PostgreSQL, Redis only where measured, Alembic, and outbox semantics.
4. **Operational truth:** AH-024-AH-026 and the remaining AH-027 contract/reliability matrix.
5. **First customer journey:** AH-029-AH-036 in dependency order: login, connection, inventory, policy, approval, receipt, incident, usage.
6. **Adoption surface:** AH-037-AH-045, with marketing rebuilt from verified proof rather than promises.
7. **Pilot gate:** measure reliability, customer ROI, and unit economics before any AH-046-AH-052 work.

## Product Completion Gate

The local API now proves the separate-server import-to-revocation sequence. AgentHub is still not a functional customer product until that sequence is available through a real authenticated human journey with shared durable state, observable operation, exact deployment evidence, and no simulated result counted as success.
