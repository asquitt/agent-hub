# Discovery MCP Tools (D12)

## Exposed Tools
- `search_capabilities(query, constraints)`
- `get_agent_manifest(agent_id, version)`
- `check_compatibility(my_schema, agent_id)`

## Agent-Native Guarantees
- Cached contract and compatibility paths optimized for low latency.
- Cost constraint optimization support (`max_cost_usd`) in semantic discovery.
- Schema compatibility report for strict runtime delegation checks.

## A2A Card
A2A publishing artifact is available at:
- `/.well-known/agent-card.json`
