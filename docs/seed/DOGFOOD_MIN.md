# Seed Dogfooding (D17 minimum)

## Seed Agents Included (Minimum Set)
- `seed/agents/web-researcher.yaml`
- `seed/agents/data-normalizer.yaml`
- `seed/agents/pipeline-planner.yaml`

## Minimum Dogfooding Evidence
- `pipeline-planner` consumes capability discovery outputs to produce recommendations.
- Delegation path exercised through D13 APIs with lifecycle + audit evidence.

## CLI Workflow Used
```bash
agenthub validate seed/agents/web-researcher.yaml --json
agenthub publish seed/agents/web-researcher.yaml --namespace @seed --local --json
agenthub publish seed/agents/data-normalizer.yaml --namespace @seed --local --json
agenthub publish seed/agents/pipeline-planner.yaml --namespace @seed --local --json
agenthub search "normalize records" --local --json
agenthub versions @seed:pipeline-planner --local --json
```
