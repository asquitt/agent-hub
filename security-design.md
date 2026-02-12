# AgentHub Security Design (D04)

## Security Objectives
- Enforce least privilege across users, agents, and system services.
- Prevent unsafe delegation by default via policy-first controls.
- Produce auditable, tamper-evident operational records.

## API Key Management
- API keys are generated as random high-entropy tokens and shown once at creation.
- Persist only key hashes (`api_key_hash`) in Postgres; never store plaintext keys.
- Keys are scoped by principal (user/org/agent) and permission profile.
- Key rotation policy:
  - Standard keys: rotate every 90 days
  - Privileged keys: rotate every 30 days
- Compromised key response:
  - Immediate revoke
  - Re-issue scoped replacement
  - Incident log with actor and affected resources

## Authentication and Authorization Model
- Human auth: OIDC (Clerk/Auth0) with session tokens.
- Agent auth: signed JWT or short-lived scoped API keys.
- Service-to-service auth: mTLS + workload identity where supported.

## RBAC Model
Roles:
- `owner`: namespace/org ownership, billing and policy admin
- `admin`: agent publication, key management, trust policy updates
- `maintainer`: manifest/version updates, eval runs
- `viewer`: read-only access

Permission examples:
- `agents.publish`
- `agents.update`
- `keys.rotate`
- `billing.read`
- `delegation.approve_high_risk`

Access checks:
- RBAC check at API boundary
- Resource ownership check at domain layer
- High-risk action approval requirement when policy flags are triggered

## Rate Limiting and Abuse Controls
- Multi-dimensional rate limits:
  - Per IP for anonymous traffic
  - Per API key for authenticated traffic
  - Per agent identity for runtime calls
- Token bucket implementation with burst allowances and endpoint-specific quotas.
- Automatic challenge/throttle for anomalous request patterns.

## Secrets and Credential Handling
- Secrets stored in cloud secrets manager/KMS-backed vaults.
- Runtime credentials are short-lived and scoped.
- Secret material never logged; logs store deterministic hashes only.

## Logging and Audit Requirements
All privileged actions must log:
- actor
- tool/endpoint
- input hash
- output hash
- cost
- timestamp
- decision result

Audit logs are immutable and exported daily to archive storage.

## Prompt Injection and Tool Output Hardening
- Treat all tool inputs/outputs as untrusted.
- Enforce schema validation and allow-list checks before side effects.
- Strip or quarantine suspicious instruction-like payloads crossing trust boundaries.

## Incident Response and DR Security Alignment
- Incident severity matrix with pager escalation for critical auth/privilege failures.
- RTO `< 4h`, RPO `< 1h` aligned with architecture DR targets.
- Quarterly tabletop and recovery drills include compromised credential scenarios.
