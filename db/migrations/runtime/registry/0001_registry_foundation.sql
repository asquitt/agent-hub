CREATE TABLE IF NOT EXISTS registry_namespaces (
  namespace TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS registry_agents (
  agent_id TEXT PRIMARY KEY,
  namespace TEXT NOT NULL,
  slug TEXT NOT NULL,
  owner TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS registry_agent_versions (
  agent_id TEXT NOT NULL,
  version TEXT NOT NULL,
  manifest_json TEXT NOT NULL,
  eval_summary_json TEXT NOT NULL DEFAULT '{"tier1":"pending","tier2":"pending","tier3":"pending"}',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  PRIMARY KEY (agent_id, version),
  FOREIGN KEY (agent_id) REFERENCES registry_agents(agent_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_registry_agents_namespace_status
  ON registry_agents(namespace, status);

CREATE INDEX IF NOT EXISTS idx_registry_agent_versions_created
  ON registry_agent_versions(agent_id, created_at);
