---
name: project-quality
description: Enforce AgentHub's autonomous delivery, verification, and exact-review standard for non-trivial implementation, bug-fix, security, persistence, UI, and release work.
---

# AgentHub Project Quality

Use this workflow for any non-trivial change. Read `AGENTS.md`, `CLAUDE.md`, and the closest scoped instructions before editing.

## Execute

1. Inspect `git status -sb` and preserve unrelated work.
2. State assumptions, scope, and measurable success criteria.
3. Search identity, registry, policy, delegation, discovery, lease, federation, provenance, billing, marketplace, and runtime modules before creating a new concern home.
4. Reproduce bugs or contract gaps with the narrowest useful test.
5. Implement the smallest complete fix and update every touched caller, export, registry, migration, and contract.

## Verify

Run the narrowest pytest target first, then relevant Makefile lint, packaging, deployment, and Playwright gates; use the full suite only at an actual release boundary where its cost and known baseline are understood.

Do not infer success from a status flag, HTTP 200, mock, or healthy container alone. Inspect credential or capability ownership, policy decision, persisted delegation or lease, revocation behavior, audit provenance, and the operator-visible result. Exercise negative authorization and failure or recovery cases whenever those boundaries changed.

## Review and handoff

Material production, security, isolation, autonomous-mutation, persistence, provider-routing, or public-UI changes require the independent exact-commit review in `.github/ai-review/senior-review.md`. HIGH or MEDIUM findings block merge or deployment.

Report exact branch and head, tests and probes run, runtime or public evidence, review status, rollback and cleanup state, and anything still unverified. Never fabricate evidence.
