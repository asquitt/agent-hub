# S52 GA Rehearsal Runbook

## Command
```bash
python3 tools/launch/rehearse_ga_candidate.py
```

## Expected Outputs
- Console JSON with:
  - `checks`
  - `incident_drills.passed`
  - `rollback_simulation.passed`
  - `gate_review.decision`
  - `ga_candidate_ready`
- Report files:
  - `docs/launch/S52_LAUNCH_REHEARSAL.json`
  - `docs/launch/S52_LAUNCH_REHEARSAL.md`

## Drill Coverage
1. Demo reproducibility across launch API surfaces.
2. Onboarding funnel threshold validation.
3. Incident drill: policy approval bypass prevention.
4. Incident drill: owner-boundary enforcement on lease promotion.
5. Incident drill: attestation integrity mismatch rejection.
6. Rollback simulation: promote to install, rollback, and idempotent rollback replay.
7. GA gate inheritance from latest gate review artifact.
