-- S163: Record explicit operator assignment of quarantined legacy identities.
CREATE TABLE IF NOT EXISTS identity_quarantine_assignments (
  assignment_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL UNIQUE,
  owner TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  assigned_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  FOREIGN KEY (agent_id) REFERENCES agent_identities(agent_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_identity_quarantine_assignments_owner_tenant
  ON identity_quarantine_assignments(owner, tenant_id, assigned_at DESC);

CREATE TRIGGER IF NOT EXISTS identity_quarantine_assignments_no_update
BEFORE UPDATE ON identity_quarantine_assignments
BEGIN
  SELECT RAISE(ABORT, 'identity quarantine assignments are append-only');
END;

CREATE TRIGGER IF NOT EXISTS identity_quarantine_assignments_no_delete
BEFORE DELETE ON identity_quarantine_assignments
BEGIN
  SELECT RAISE(ABORT, 'identity quarantine assignments are append-only');
END;
