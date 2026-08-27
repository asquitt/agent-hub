# AgentHub AGENTS.md

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
Build AgentHub as a trustworthy interoperability and runtime infrastructure layer for autonomous agents, with a staged rollout that prioritizes reliability and unit economics before marketplace expansion.

## Non-Negotiables
1. Every completed segment must include implementation, verification, and evidence.
2. Every completed segment must update:
   - `docs/agenthub-master-plan-v1.2.docx` (or `docs/agenthub-master-plan.docx`)
   - `docs/DELIVERABLE_LOG.md`
3. No segment is complete until tests run and evidence is recorded.
4. No architecture decision should be justified by intuition alone when external evidence exists.

## V1 Scope (Build First)
- D01, D02, D03, D04, D05, D09, D11, D12, D13, D08 (minimum), D17 (minimum)

## Deferred Until Gate Criteria Pass
- D07 full, D06, D10, D14 full promotion path, D15, D16, D18

Gate criteria:
- Reliability target met in pilot workloads
- Positive design-partner ROI evidence
- Sustainable unit economics under real multi-agent load

## Architecture Decisions (Research-Informed)

### 1) Start with simple workflows, then add autonomy
- Default to deterministic workflow orchestration first.
- Add open-ended agent loops only when metrics show clear lift.
- Rationale: proven guidance from Anthropic and OpenAI to avoid premature complexity.

### 2) Canonical internal contract + protocol adapters
- Internal canonical schema is source of truth.
- Adapters expose MCP first, then A2A.
- Do not fork business logic per protocol.

### 3) Policy-first capability discovery
- Enforce hard constraints before semantic ranking:
  - Permissions
  - Trust threshold
  - Budget limits
  - Contract compatibility
- Semantic relevance only ranks among policy-compliant candidates.

### 4) Lease-first capability acquisition
- Default: temporary leased capability with TTL.
- Persistent install requires policy checks and explicit approval path.

### 5) Cost guardrails for delegation
- Budget thresholds:
  - 80%: soft alert
  - 100%: mandatory re-authorization
  - 120%: hard stop
- All delegation calls must be metered and auditable.

### 6) Tool-call reliability and idempotency
- Assume duplicate and repeated tool calls can happen.
- Require idempotency keys for all writes.
- Keep side effects idempotent and replay-safe.

### 7) Structured outputs by default
- Use strict schemas for tool outputs.
- Reject malformed outputs early with deterministic validators.

## Security Baseline
1. Treat all tool inputs/tool outputs as untrusted by default.
2. Sandbox delegated execution.
3. Enforce least privilege for tool access and secrets.
4. Use scoped, short-lived credentials where possible.
5. Add explicit high-risk action approvals.
6. Log all privileged actions with actor, tool, input hash, output hash, cost, and timestamp.

## Segment Workflow (Codex Sessions)
For each segment `Sxx`:
1. Create `docs/session-packets/Sxx.md` from template.
2. Implement only in-scope changes.
3. Run required tests.
4. Write evidence to `docs/evidence/Sxx.md`.
5. Update `docs/DELIVERABLE_LOG.md`.
6. Update `docs/agenthub-master-plan-v1.2.docx` status/notes.

## Required Deliverables Per Segment
- Code changes
- Test results
- Verification evidence
- Risks/open issues
- Handoff instructions for the next segment

## Segment Map
- S01 -> D01
- S02 -> D02
- S03 -> D03 + D04
- S04 -> D05
- S05 -> D09
- S06 -> D11
- S07 -> D12
- S08 -> D13
- S09 -> D08 + D17 (minimum)
- S10 -> Gate review
- S11 -> D07 (minimum operator UI)
- S12 -> D06 + D10
- S13 -> D14
- S14 -> D15
- S15 -> D16
- S16 -> D18

## Verification Requirements

### API/Contract
- Schema conformance tests
- Negative tests for malformed input/output
- Backward-compatibility tests for adapters

### Reliability
- Retry/idempotency tests
- Timeout/circuit-breaker behavior tests
- Deterministic replay of key workflows

### Security
- Prompt-injection resistance tests
- Privilege boundary tests
- Secret handling checks

### Cost and Performance
- Budget guardrail tests
- Latency checks for key endpoints
- Cost-per-task tracking and variance checks

## Definition of Done
A segment is done only when:
1. Acceptance criteria are met.
2. Tests pass and are recorded.
3. Evidence file is complete.
4. `docs/DELIVERABLE_LOG.md` is updated.
5. `docs/agenthub-master-plan-v1.2.docx` is updated with progress.

## Reference Summary (Research Inputs)
- Anthropic engineering guidance on agent workflows and multi-agent tradeoffs
- OpenAI developer docs/blog on agents, tools, evals, and reliability patterns
- OpenAI developer forum issues on tool-calling edge cases and workarounds
- Reddit practitioner reports (anecdotal) on tooling reliability, local model limits, and orchestration pitfalls

See `docs/RESEARCH_INSIGHTS.md` for source links and extracted decisions.

## Git persistence

Commit coherent, verified segments without altering remotes or branch identity. Push once at the requested or final handoff boundary, and report the exact branch and head SHA.
