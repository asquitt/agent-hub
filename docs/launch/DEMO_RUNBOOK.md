# S16 Demo Runbook

## Command
```bash
python3 tools/launch/check_launch_readiness.py
```

## GA Rehearsal Command (S52)
```bash
python3 tools/launch/rehearse_ga_candidate.py
```

## Expected Outputs
- Console JSON with:
  - `demo_reproducibility.passed`
  - `onboarding_funnel.passed`
  - `launch_ready`
- Report file:
  - `docs/launch/S16_READINESS.json`
- GA rehearsal JSON with:
  - `incident_drills.passed`
  - `rollback_simulation.passed`
  - `gate_review.decision`
  - `ga_candidate_ready`
- GA rehearsal report files:
  - `docs/launch/S52_LAUNCH_REHEARSAL.json`
  - `docs/launch/S52_LAUNCH_REHEARSAL.md`

## Demo Coverage
1. Health endpoint availability.
2. Agent registration and retrieval.
3. Capability search.
4. Operator dashboard read path.
5. Onboarding funnel conversion threshold checks.
6. Policy-boundary incident drills and rollback simulation.
