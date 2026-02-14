-- S75: Trust registry for cross-org federation
CREATE TABLE IF NOT EXISTS trusted_domains (
  domain_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  trust_level TEXT NOT NULL DEFAULT 'verified',  -- 'verified' | 'provisional' | 'revoked'
  public_key_pem TEXT,
  allowed_scopes_json TEXT NOT NULL DEFAULT '[]',
  registered_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS agent_attestations (
  attestation_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  domain_id TEXT NOT NULL,
  claims_json TEXT NOT NULL DEFAULT '{}',
  issued_at_epoch INTEGER NOT NULL,
  expires_at_epoch INTEGER NOT NULL,
  signature TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (agent_id) REFERENCES agent_identities(agent_id),
  FOREIGN KEY (domain_id) REFERENCES trusted_domains(domain_id)
);

CREATE INDEX IF NOT EXISTS idx_attestations_agent ON agent_attestations(agent_id);
CREATE INDEX IF NOT EXISTS idx_attestations_domain ON agent_attestations(domain_id);
