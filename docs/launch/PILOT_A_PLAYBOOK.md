# Design-Partner Pilot A Playbook (S26)

## Objective
Validate reliability, connector-depth coverage, and ROI controls for Pilot A workloads.

## Weekly Runbook
1. Execute core delegation workflow against pilot workload.
2. Export KPI snapshot:
   - `python3 tools/pilots/export_pilot_metrics.py --pilot-id pilot-a --output data/pilots/pilot_a_weekly.json`
3. Review expanded metrics in output payload:
   - `metrics.connectors`
   - `metrics.workloads`
   - `metrics.roi`
4. Review incidents against `docs/launch/INCIDENT_TAXONOMY.md`.
5. Archive evidence in `docs/evidence/S26.md`.

## KPI Targets
- Delegation success rate >= 0.99
- Hard-stop bypass incidents = 0
- Unresolved critical incidents = 0
- Connector coverage ratio >= 0.80
- Planned weekly workload coverage >= 120 tasks
- Net ROI (`metrics.roi.net_roi_usd`) > 0
