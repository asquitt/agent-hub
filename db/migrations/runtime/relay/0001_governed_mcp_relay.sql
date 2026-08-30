CREATE TABLE IF NOT EXISTS relay_targets (
    target_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    endpoint_url TEXT NOT NULL,
    endpoint_digest TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    server_name TEXT NOT NULL,
    server_version TEXT NOT NULL,
    protocol_version TEXT NOT NULL,
    input_schema_json TEXT NOT NULL,
    output_schema_json TEXT NOT NULL,
    schema_digest TEXT NOT NULL,
    annotations_json TEXT NOT NULL,
    max_call_cost_usd REAL NOT NULL CHECK (max_call_cost_usd >= 0),
    policy_revision TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    imported_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS relay_budget_accounts (
    owner TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    capability_token_id TEXT NOT NULL,
    max_budget_usd REAL NOT NULL CHECK (max_budget_usd > 0),
    spent_usd REAL NOT NULL DEFAULT 0 CHECK (spent_usd >= 0),
    reserved_usd REAL NOT NULL DEFAULT 0 CHECK (reserved_usd >= 0),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (owner, tenant_id, capability_token_id)
);

CREATE TABLE IF NOT EXISTS relay_invocations (
    invocation_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    target_id TEXT NOT NULL REFERENCES relay_targets(target_id),
    capability_token_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed', 'indeterminate')),
    input_hash TEXT NOT NULL,
    output_hash TEXT,
    result_json TEXT,
    error_code TEXT,
    error_message TEXT,
    policy_json TEXT,
    budget_json TEXT,
    receipt_json TEXT,
    reserved_cost_usd REAL NOT NULL DEFAULT 0 CHECK (reserved_cost_usd >= 0),
    charged_cost_usd REAL NOT NULL DEFAULT 0 CHECK (charged_cost_usd >= 0),
    network_started_at TEXT,
    remote_result_observed INTEGER NOT NULL DEFAULT 0 CHECK (remote_result_observed IN (0, 1)),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 1),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    completed_at TEXT,
    UNIQUE (owner, tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_relay_invocations_actor
    ON relay_invocations(owner, tenant_id, agent_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_relay_invocations_pending
    ON relay_invocations(status, network_started_at);
