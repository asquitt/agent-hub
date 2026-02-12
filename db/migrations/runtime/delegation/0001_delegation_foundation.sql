CREATE TABLE IF NOT EXISTS delegation_records (
  delegation_id TEXT PRIMARY KEY,
  requester_agent_id TEXT NOT NULL,
  delegate_agent_id TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS delegation_balances (
  agent_id TEXT PRIMARY KEY,
  balance_usd REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_delegation_records_requester
  ON delegation_records(requester_agent_id, updated_at);

CREATE INDEX IF NOT EXISTS idx_delegation_records_delegate
  ON delegation_records(delegate_agent_id, updated_at);
