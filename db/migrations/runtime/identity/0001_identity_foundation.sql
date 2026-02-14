CREATE TABLE IF NOT EXISTS agent_identities (
  agent_id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  credential_type TEXT NOT NULL DEFAULT 'api_key',
  status TEXT NOT NULL DEFAULT 'active',
  public_key_pem TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_agent_identities_owner
  ON agent_identities(owner);

CREATE INDEX IF NOT EXISTS idx_agent_identities_owner_status
  ON agent_identities(owner, status);

CREATE TABLE IF NOT EXISTS agent_credentials (
  credential_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  credential_hash TEXT NOT NULL,
  scopes_json TEXT NOT NULL DEFAULT '[]',
  issued_at_epoch INTEGER NOT NULL,
  expires_at_epoch INTEGER NOT NULL,
  rotation_parent_id TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  revoked_at TEXT,
  revocation_reason TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (agent_id) REFERENCES agent_identities(agent_id)
);

CREATE INDEX IF NOT EXISTS idx_agent_credentials_agent
  ON agent_credentials(agent_id, status);

CREATE INDEX IF NOT EXISTS idx_agent_credentials_expires
  ON agent_credentials(expires_at_epoch);

CREATE INDEX IF NOT EXISTS idx_agent_credentials_hash
  ON agent_credentials(credential_hash);
