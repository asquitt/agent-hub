# S16 Demo Runbook

## Command
```bash
python3 tools/launch/check_launch_readiness.py
```

## Expected Outputs
- Console JSON with:
  - `demo_reproducibility.passed`
  - `onboarding_funnel.passed`
  - `launch_ready`
- Report file:
  - `docs/launch/S16_READINESS.json`

## Demo Coverage
1. Health endpoint availability.
2. Agent registration and retrieval.
3. Capability search.
4. Operator dashboard read path.
5. Onboarding funnel conversion threshold checks.
