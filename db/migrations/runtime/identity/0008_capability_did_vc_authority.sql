-- S165: durable, tenant-owned authority for capability tokens, DIDs, and VCs.
CREATE TABLE IF NOT EXISTS capability_token_roots (
  token_id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  issuer_agent_id TEXT NOT NULL,
  subject_agent_id TEXT NOT NULL,
  issuer_generation TEXT NOT NULL,
  subject_generation TEXT NOT NULL,
  audience TEXT NOT NULL,
  resource TEXT NOT NULL,
  scopes_json TEXT NOT NULL,
  issued_at_epoch REAL NOT NULL,
  expires_at_epoch REAL NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
  revoked_at TEXT,
  revocation_reason TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (issuer_agent_id) REFERENCES agent_identities(agent_id) ON DELETE RESTRICT,
  FOREIGN KEY (subject_agent_id) REFERENCES agent_identities(agent_id) ON DELETE RESTRICT,
  CHECK (length(trim(audience)) > 0),
  CHECK (length(trim(resource)) > 0),
  CHECK (expires_at_epoch > issued_at_epoch)
);

CREATE INDEX IF NOT EXISTS idx_capability_token_roots_boundary
  ON capability_token_roots(owner, tenant_id, issued_at_epoch DESC);
CREATE INDEX IF NOT EXISTS idx_capability_token_roots_issuer
  ON capability_token_roots(owner, tenant_id, issuer_agent_id, revoked);
CREATE INDEX IF NOT EXISTS idx_capability_token_roots_subject
  ON capability_token_roots(owner, tenant_id, subject_agent_id, revoked);

CREATE TABLE IF NOT EXISTS agent_dids (
  did TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  agent_id TEXT NOT NULL UNIQUE,
  identity_generation TEXT NOT NULL,
  document_json TEXT NOT NULL,
  deactivated INTEGER NOT NULL DEFAULT 0 CHECK (deactivated IN (0, 1)),
  deactivated_at TEXT,
  deactivation_reason TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (agent_id) REFERENCES agent_identities(agent_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_agent_dids_boundary
  ON agent_dids(owner, tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS verifiable_credentials (
  vc_id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  issuer_did TEXT NOT NULL,
  subject_did TEXT NOT NULL,
  issuer_generation TEXT NOT NULL,
  subject_generation TEXT NOT NULL,
  credential_type TEXT NOT NULL,
  record_json TEXT NOT NULL,
  issued_at_epoch REAL NOT NULL,
  expires_at_epoch REAL NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
  revoked_at TEXT,
  revocation_reason TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (issuer_did) REFERENCES agent_dids(did) ON DELETE RESTRICT,
  FOREIGN KEY (subject_did) REFERENCES agent_dids(did) ON DELETE RESTRICT,
  CHECK (expires_at_epoch > issued_at_epoch)
);

CREATE INDEX IF NOT EXISTS idx_verifiable_credentials_boundary
  ON verifiable_credentials(owner, tenant_id, issued_at_epoch DESC);
CREATE INDEX IF NOT EXISTS idx_verifiable_credentials_issuer
  ON verifiable_credentials(owner, tenant_id, issuer_did, revoked);
CREATE INDEX IF NOT EXISTS idx_verifiable_credentials_subject
  ON verifiable_credentials(owner, tenant_id, subject_did, revoked);
