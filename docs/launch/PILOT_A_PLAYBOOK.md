# Design-Partner Pilot A Playbook (S26)

## Objective
Validate reliability and cost controls for a document-processing delegation workflow.

## Weekly Runbook
1. Execute core delegation workflow against pilot workload.
2. Export KPI snapshot:
   - `python3 tools/pilots/export_pilot_metrics.py --pilot-id pilot-a --output data/pilots/pilot_a_weekly.json`
3. Review incidents against `docs/launch/INCIDENT_TAXONOMY.md`.
4. Archive evidence in `docs/evidence/S26.md`.

## KPI Targets
- Delegation success rate >= 0.99
- Hard-stop bypass incidents = 0
- Unresolved critical incidents = 0
