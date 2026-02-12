# Design-Partner Pilot B Playbook (S27)

## Objective
Validate the same runtime controls in a second vertical and compare reliability/cost/trust trends with Pilot A.

## Weekly Runbook
1. Run delegated workflow set for pilot B.
2. Export KPI snapshot:
   - `python3 tools/pilots/export_pilot_metrics.py --pilot-id pilot-b --output data/pilots/pilot_b_weekly.json`
3. Generate pilot comparison report:
   - `python3 tools/pilots/compare_pilots.py --pilot-a data/pilots/pilot_a_weekly.json --pilot-b data/pilots/pilot_b_weekly.json --output data/pilots/pilot_comparison.json`
4. Archive evidence in `docs/evidence/S27.md`.

## KPI Targets
- Reliability non-regression versus Pilot A
- Cost variance trend non-increasing versus Pilot A
- No increase in unresolved critical incidents
