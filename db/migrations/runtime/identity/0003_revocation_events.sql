-- S74: Revocation events table for audit trail and kill switch
CREATE TABLE IF NOT EXISTS revocation_events (
  event_id TEXT PRIMARY KEY,
  revoked_type TEXT NOT NULL,           -- 'credential' | 'delegation_token' | 'agent_identity'
  revoked_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT 'manual_revocation',
  actor TEXT NOT NULL,                  -- owner who initiated
  cascade_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_revocation_events_agent ON revocation_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_revocation_events_type ON revocation_events(revoked_type);
CREATE INDEX IF NOT EXISTS idx_revocation_events_created ON revocation_events(created_at DESC);
