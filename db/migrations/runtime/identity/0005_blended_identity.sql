-- S99: Blended Identity + Configuration Checksums
-- human_principal_id: binds an agent identity to a human principal (on-behalf-of)
-- configuration_checksum: SHA-256 of the agent's configuration for integrity verification

ALTER TABLE agent_identities ADD COLUMN human_principal_id TEXT DEFAULT NULL;
ALTER TABLE agent_identities ADD COLUMN configuration_checksum TEXT DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_agent_identities_human_principal
  ON agent_identities(human_principal_id)
  WHERE human_principal_id IS NOT NULL;
