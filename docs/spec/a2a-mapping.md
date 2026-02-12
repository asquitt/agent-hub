# AgentHub Manifest to A2A Mapping (v0.1)

## Scope
Defines projection rules between AgentHub `agent.yaml` and A2A `.well-known/agent-card.json`.

## Direction 1: AgentHub -> A2A Agent Card

| AgentHub field | A2A field | Rule |
|---|---|---|
| `identity.id` | `id` | Copy as-is. |
| `identity.name` | `name` | Copy as-is. |
| `identity.description` | `description` | Copy as-is. |
| `identity.version` | `version` | Copy as-is. |
| `interfaces[protocol=A2A].endpoint` | `url` | First matching A2A endpoint. |
| `capabilities[*].id` | `skills[*].id` | One skill per capability. |
| `capabilities[*].name` | `skills[*].name` | Copy as-is. |
| `capabilities[*].description` | `skills[*].description` | Copy as-is. |
| `capabilities[*].input_schema` | `skills[*].input_schema` | Preserve JSON schema object or `$ref_uri`. |
| `capabilities[*].output_schema` | `skills[*].output_schema` | Preserve JSON schema object or `$ref_uri`. |
| `capabilities[*].protocols` | `skills[*].protocols` | Copy enum list. |
| `trust.minimum_trust_score` | `security.minimum_trust_score` | Copy numeric threshold. |
| `trust.allowed_trust_sources` | `security.allowed_sources` | Copy array. |
| `trust.policy.*` | `security.policy.*` | Copy one-to-one. |
| `trust.budget_guardrails.*` | `economics.guardrails.*` | Copy one-to-one. |
| `provenance.*` | `meta.provenance.*` | Preserve under namespaced metadata. |

## Direction 2: A2A Agent Card -> AgentHub Projection

| A2A field | AgentHub field | Rule |
|---|---|---|
| `id` | `identity.id` | Required; reject if missing. |
| `name` | `identity.name` | Required; reject if missing. |
| `description` | `identity.description` | Required; reject if missing. |
| `version` | `identity.version` | Must satisfy semver. |
| `url` | `interfaces[]` | Create `A2A` interface with `endpoint=url`. |
| `skills[]` | `capabilities[]` | Convert each skill to one capability. |
| `security.minimum_trust_score` | `trust.minimum_trust_score` | Required fallback: `0.7` if absent. |
| `security.allowed_sources` | `trust.allowed_trust_sources` | Required fallback: `['first_party']`. |
| `security.policy.*` | `trust.policy.*` | Required defaults if absent. |
| `economics.guardrails.*` | `trust.budget_guardrails.*` | Must resolve to `80/100/120`, else reject for v0.1. |
| `meta.provenance.*` | `provenance.*` | Copy if available. |

## Unsupported/Partial Field Policy
- Any A2A field with no canonical AgentHub target is preserved under `provenance.source = imported` and adapter metadata namespace during import.
- Any AgentHub field with no A2A representation is emitted under `meta.agenthub_extensions.*` during export.
- Adapter must never silently remap privileged permissions. Unknown permission semantics are rejected.
- Adapter warnings are required whenever fields are dropped.

## Validation Constraints During Mapping
- Privileged interfaces in AgentHub require explicit permissions before export.
- Secret references remain references; no secret material may be emitted to agent cards.
- Capability schemas must remain structured objects or resolvable references.
