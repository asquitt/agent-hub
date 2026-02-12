# AgentHub Manifest to MCP Mapping (v0.1)

## Scope
Defines deterministic projection from AgentHub capability declarations to MCP tool declarations.

## Field-by-Field Mapping

| AgentHub field | MCP field | Rule |
|---|---|---|
| `identity.id` | `server.name` | Copy as server identity slug. |
| `identity.version` | `server.version` | Copy as-is. |
| `identity.description` | `server.description` | Copy as-is. |
| `interfaces[protocol=MCP].endpoint` | MCP transport endpoint | Use first MCP interface endpoint. |
| `capabilities[*].id` | `tools[*].name` | Tool name = capability id. |
| `capabilities[*].description` | `tools[*].description` | Copy as-is. |
| `capabilities[*].input_schema` | `tools[*].inputSchema` | Schema translation rules below. |
| `capabilities[*].output_schema` | `tools[*].outputSchema` | Schema translation rules below. |
| `capabilities[*].permissions` | `tools[*].annotations.permissions` | Preserve permission scopes. |
| `capabilities[*].idempotency_key_required` | `tools[*].annotations.idempotency.required` | Copy boolean. |
| `capabilities[*].side_effect_level` | `tools[*].annotations.sideEffects` | Map `none|low|high` directly. |
| `trust.policy.high_risk_approval_required` | `tools[*].annotations.requiresApproval` | Copy boolean for privileged or high-risk calls. |
| `trust.budget_guardrails.*` | `tools[*].annotations.budgetGuardrails.*` | Copy threshold constants. |

## Schema Translation Rules
1. If capability schema is inline JSON schema (`type`, `properties`, etc.), copy directly.
2. If capability schema is reference form (`$ref_uri`), emit MCP schema wrapper:
   - `{"$ref": "$ref_uri"}`
3. `required` arrays are preserved.
4. `additionalProperties` defaults to `false` only when explicitly set in AgentHub schema; otherwise preserve original behavior.
5. Non-object top-level input schemas are allowed but discouraged; validator should warn.

## Unsupported/Partial Field Policy
- `composition` has no direct MCP equivalent; expose under server metadata extension `agenthub.composition`.
- `runtime` fields remain agent-level metadata, not per-tool MCP fields.
- Unknown AgentHub fields are not projected unless prefixed under approved extension namespace.
- Adapter must emit warnings for dropped fields and include original path list.

## Safety Requirements
- No secret values may be present in generated MCP tool metadata.
- Privileged capability permissions must be preserved exactly.
- Tool declarations with side effects must include idempotency annotation.
