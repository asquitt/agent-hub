-- S163: Add immutable tenant attribution without guessing legacy ownership.
-- Existing rows remain queryable for migration tooling but are quarantined from
-- authenticated resource paths until an operator performs an explicit assignment.

ALTER TABLE agent_identities ADD COLUMN tenant_id TEXT DEFAULT NULL;
ALTER TABLE agent_identities
  ADD COLUMN tenancy_status TEXT NOT NULL DEFAULT 'quarantined'
  CHECK (tenancy_status IN ('active', 'quarantined'));

ALTER TABLE delegation_tokens ADD COLUMN owner TEXT DEFAULT NULL;
ALTER TABLE delegation_tokens ADD COLUMN tenant_id TEXT DEFAULT NULL;

ALTER TABLE revocation_events ADD COLUMN owner TEXT DEFAULT NULL;
ALTER TABLE revocation_events ADD COLUMN tenant_id TEXT DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_agent_identities_owner_tenant
  ON agent_identities(owner, tenant_id, tenancy_status);

CREATE INDEX IF NOT EXISTS idx_delegation_tokens_owner_tenant
  ON delegation_tokens(owner, tenant_id, token_id);

CREATE INDEX IF NOT EXISTS idx_revocation_events_owner_tenant_created
  ON revocation_events(owner, tenant_id, created_at DESC);
