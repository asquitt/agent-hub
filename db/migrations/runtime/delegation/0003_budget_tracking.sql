-- Per-delegation-token budget tracking with cost events.

CREATE TABLE IF NOT EXISTS delegation_budget_events (
    event_id TEXT PRIMARY KEY,
    token_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'tenant-default',
    actor TEXT NOT NULL,
    cost_usd REAL NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_budget_events_token
    ON delegation_budget_events(token_id);

CREATE TABLE IF NOT EXISTS delegation_budget_limits (
    token_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'tenant-default',
    max_budget_usd REAL NOT NULL DEFAULT 10.0,
    soft_alert_pct REAL NOT NULL DEFAULT 80.0,
    reauth_pct REAL NOT NULL DEFAULT 100.0,
    hard_stop_pct REAL NOT NULL DEFAULT 120.0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
