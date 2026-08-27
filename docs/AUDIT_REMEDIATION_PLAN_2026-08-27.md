# AgentHub Audit Remediation Plan

## Current Verdict

**NO-GO for production or customer pilots.** The merged `main` baseline at `c2c0d7cec6eed317882c497bf8c114b5be60ed4b` is materially safer than the February audit target, but it remains a single-process local control-plane prototype. Identity authority, revocation-aware verification, and inbound MCP discovery are real within documented local boundaries. Remote workload invocation, action receipts, webhook delivery, distributed persistence, production deployment, and customer outcomes are not proven.

The local post-merge baseline is `758 passed, 1 skipped`; the skipped test is the opt-in official MCP SDK interpreter lane. This is repository evidence only, not hosted CI, deployment, provider, or customer evidence.

## Status Definitions

- `COMPLETE_LOCAL`: exit criterion is proven locally within an explicit boundary.
- `PARTIAL`: reusable implementation exists, but the exit criterion is not met.
- `IN_PROGRESS`: the current S166 candidate is implementing the remaining containment.
- `UNSTARTED`: no implementation satisfies the exit criterion.
- `DEFERRED`: intentionally blocked behind pilot gates.

## P0A: Containment And Truth

| ID | Status | Current disposition |
|---|---|---|
| AH-001 | IN_PROGRESS | Freeze remains the default; S167 is the only approved new product path because it replaces a simulator with the required real invocation boundary. |
| AH-002 | IN_PROGRESS | S166 labels every OpenAPI operation `prototype`, `stub`, or `deferred`; exact-candidate verification remains. |
| AH-003 | IN_PROGRESS | S166 corrects README, marketing, runtime, webhook, OpenAPI, and ledger claims. |
| AH-004 | PARTIAL | Full local suite is green; automatic required hosted CI remains intentionally disabled and unproven. |
| AH-005 | PARTIAL | Strict local dependency audits have passed; no provider-enforced blocking gate is proven. |
| AH-006 | COMPLETE_LOCAL | Typed auth context preserves owner, tenant, scopes, roles, auth method, agent, and delegation metadata. |
| AH-007 | IN_PROGRESS | Identity/vault boundaries are repaired; S166 closes reproduced cross-owner delegation status. Comprehensive object authorization remains a continuing gate. |
| AH-008 | COMPLETE_LOCAL | OAuth client grants are durable and requested scopes are attenuated to registered authority. |
| AH-009 | IN_PROGRESS | One worker/replica is configured; S166 adds declared-topology rejection and a singleton process lock. |
| AH-010 | IN_PROGRESS | S166 default-disables unsafe billing, marketplace, procurement, and delegated charging before mutation. |
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
| AH-018 | PARTIAL | Authenticated MCP initialize/list/call exists for three local discovery tools; no upstream MCP client. |
| AH-019 | PARTIAL | Signed attenuation and durable roots exist; public schema, asymmetric verifier, and test vectors remain. |
| AH-020 | PARTIAL | Policy preflight exists but is not atomic at a real outbound call boundary. |
| AH-021 | UNSTARTED | No remote MCP tool is invoked. S167 is the first implementation slice. |
| AH-022 | PARTIAL | Generic symmetric provenance envelopes exist; no independently verifiable action receipt. |
| AH-023 | PARTIAL | Local revocation is durable and generation-aware; next-call remote denial is unproven. |
| AH-024 | UNSTARTED | No OpenTelemetry traces, metrics, propagation, or receipt correlation. |
| AH-025 | PARTIAL | Subscription-shaped APIs exist; S166 stops false delivery claims. HTTP delivery, retry, and durable DLQ remain. |
| AH-026 | PARTIAL | Local registry and fixture catalog exist; no official/private ingestion or package/SBOM/signature binding. |
| AH-027 | PARTIAL | Local malformed-input, restart, thread, and SQLite subprocess tests exist; no two-replica, remote MCP, crash ambiguity, or malformed upstream-output suite. |
| AH-028 | UNSTARTED | No import-to-invoke-to-receipt-to-revoke demo exists. |

## P1: Customer Product

| ID | Status | Current disposition |
|---|---|---|
| AH-029 | UNSTARTED | No human login, organizations, workspaces, or customer sessions. |
| AH-030 | PARTIAL | Registry data exists; no consolidated source/runtime/permission/health/evidence inventory. |
| AH-031 | UNSTARTED | No upstream MCP URL/OAuth/credential-reference onboarding or remote tool import. |
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
| AH-044 | UNSTARTED | S166 corrects claims only; proof-led marketing rebuild follows the real governed journey. |
| AH-045 | PARTIAL | Responsive demo pages exist; customer information architecture, shared design system, accessibility semantics, and real data states remain. |

## P2: Gate-Deferred Expansion

AH-046 exact-version assurance exchange, AH-047 evidence-backed reputation, AH-048 autonomous procurement, AH-049 marketplace, AH-050 managed runtime, AH-051 shared knowledge artifacts, and AH-052 advanced identity formats are `DEFERRED` until all of the following are measured on real governed calls:

1. Reliability target is met in pilot workloads.
2. Design partners show positive operational ROI.
3. Unit economics remain sustainable under real multi-agent load.
4. Revocation, receipts, approvals, and incident response work end to end.

## Execution Order

1. **S166, containment:** finish AH-002, AH-003, the reproduced AH-007 gap, AH-009, AH-010, and AH-013.
2. **S167, governed MCP relay v0:** one allowlisted read-only idempotent upstream tool; durable admission/outcome; Ed25519 receipt; revocation and crash-ambiguity proof. Advances AH-018 and AH-020-AH-023 plus AH-027-AH-028.
3. **Shared data authority:** AH-014-AH-017 with PostgreSQL, Redis only where measured, Alembic, and outbox semantics.
4. **Operational truth:** AH-024-AH-026 and the remaining AH-027 contract/reliability matrix.
5. **First customer journey:** AH-029-AH-036 in dependency order: login, connection, inventory, policy, approval, receipt, incident, usage.
6. **Adoption surface:** AH-037-AH-045, with marketing rebuilt from verified proof rather than promises.
7. **Pilot gate:** measure reliability, customer ROI, and unit economics before any AH-046-AH-052 work.

## Product Completion Gate

AgentHub is not a functional customer product until a separate upstream MCP server can be imported, governed, invoked, receipted, revoked, and denied on the next attempt through a real authenticated user journey, with durable state, observable operation, exact deployment evidence, and no simulated result counted as success.
