# D06 + D10 Behavioral Versioning

## Scope Implemented (S12)
- Behavioral diff engine between two manifest versions:
  - `src/versioning/behavioral_diff.py`
- API diff endpoint:
  - `GET /v1/agents/{agent_id}/versions/{base_version}/behavioral-diff/{target_version}`
- Version listing impact summary:
  - `GET /v1/agents/{agent_id}/versions` now includes `behavioral_impact_from_previous`.

## Diff Signals
- Breaking:
  - Added required input fields
  - Removed required output fields
  - Removed supported protocols
  - Side-effect escalation (`none -> low -> high`)
  - Removed capabilities
- Non-breaking:
  - Removed required input fields
  - Added required output fields
  - Added protocols
  - Added capabilities

## Output
- `compatibility`: `backward_compatible` or `breaking`
- `risk_level`: `low` / `medium` / `high`
- `regression_risk_score`: integer summary score
- Capability delta summary + classified change lists
