# D18 Launch Motion Plan

## Launch Objective
- Launch AgentHub with a reproducible technical demo and measurable onboarding funnel quality gates.

## Audience
- Design partners running multi-agent workloads
- Platform teams evaluating agent interoperability infrastructure

## Core Launch Assets
- Product narrative and architecture overview (`README.md`, master plan)
- Reproducible launch readiness checker:
  - `tools/launch/check_launch_readiness.py`
- Demo + funnel readiness report:
  - `docs/launch/S16_READINESS.json`
- GA launch rehearsal checker with incident and rollback drills:
  - `tools/launch/rehearse_ga_candidate.py`
- GA launch rehearsal report package:
  - `docs/launch/S52_LAUNCH_REHEARSAL.json`
  - `docs/launch/S52_LAUNCH_REHEARSAL.md`

## Execution Timeline
1. Week 0: Finalize release notes, run readiness checker, record evidence.
2. Week 1: Partner demos and onboarding.
3. Week 2: Collect funnel metrics and reliability feedback.
4. Week 3: Iterate pricing, docs, and onboarding based on telemetry.

## Gating Rules
- Demo reproducibility must pass.
- Onboarding funnel thresholds must pass:
  - signup_rate >= 0.15
  - activation_rate >= 0.40
  - paid_rate >= 0.20
- Incident drills must show policy boundary and attestation controls resolving simulated failures.
- Rollback simulation must pass for promote->rollback->idempotent rollback flow.
- GA candidate must inherit latest gate decision and block launch when gate review is `NO_GO`.
