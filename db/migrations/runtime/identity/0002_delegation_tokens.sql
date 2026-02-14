CREATE TABLE IF NOT EXISTS delegation_tokens (
  token_id TEXT PRIMARY KEY,
  issuer_agent_id TEXT NOT NULL,
  subject_agent_id TEXT NOT NULL,
  delegated_scopes_json TEXT NOT NULL DEFAULT '[]',
  issued_at_epoch INTEGER NOT NULL,
  expires_at_epoch INTEGER NOT NULL,
  parent_token_id TEXT,
  chain_depth INTEGER NOT NULL DEFAULT 0,
  revoked INTEGER NOT NULL DEFAULT 0,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_delegation_tokens_subject
  ON delegation_tokens(subject_agent_id, revoked);

CREATE INDEX IF NOT EXISTS idx_delegation_tokens_issuer
  ON delegation_tokens(issuer_agent_id);

CREATE INDEX IF NOT EXISTS idx_delegation_tokens_expires
  ON delegation_tokens(expires_at_epoch, revoked);

CREATE INDEX IF NOT EXISTS idx_delegation_tokens_parent
  ON delegation_tokens(parent_token_id);
