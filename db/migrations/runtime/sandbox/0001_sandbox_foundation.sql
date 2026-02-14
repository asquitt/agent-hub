-- Sandbox foundation schema: profiles, instances, executions, logs, metrics

CREATE TABLE IF NOT EXISTS sandbox_profiles (
    profile_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    cpu_cores REAL NOT NULL,
    memory_mb INTEGER NOT NULL,
    timeout_seconds INTEGER NOT NULL,
    network_mode TEXT NOT NULL DEFAULT 'disabled',
    disk_io_mb INTEGER NOT NULL DEFAULT 100,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS sandbox_instances (
    sandbox_id TEXT PRIMARY KEY,
    profile_id TEXT,
    agent_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    cpu_cores REAL NOT NULL,
    memory_mb INTEGER NOT NULL,
    timeout_seconds INTEGER NOT NULL,
    network_mode TEXT NOT NULL DEFAULT 'disabled',
    disk_io_mb INTEGER NOT NULL DEFAULT 100,
    delegation_id TEXT,
    lease_id TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    started_at TEXT,
    terminated_at TEXT,
    termination_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_sandbox_instances_agent ON sandbox_instances(agent_id);
CREATE INDEX IF NOT EXISTS idx_sandbox_instances_status ON sandbox_instances(status);
CREATE INDEX IF NOT EXISTS idx_sandbox_instances_owner ON sandbox_instances(owner);

CREATE TABLE IF NOT EXISTS sandbox_executions (
    execution_id TEXT PRIMARY KEY,
    sandbox_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    input_hash TEXT NOT NULL,
    output_hash TEXT,
    started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    completed_at TEXT,
    duration_ms REAL,
    exit_code INTEGER,
    error_message TEXT,
    FOREIGN KEY (sandbox_id) REFERENCES sandbox_instances(sandbox_id)
);

CREATE INDEX IF NOT EXISTS idx_sandbox_executions_sandbox ON sandbox_executions(sandbox_id);
CREATE INDEX IF NOT EXISTS idx_sandbox_executions_agent ON sandbox_executions(agent_id);
CREATE INDEX IF NOT EXISTS idx_sandbox_executions_status ON sandbox_executions(status);

CREATE TABLE IF NOT EXISTS sandbox_logs (
    log_id TEXT PRIMARY KEY,
    sandbox_id TEXT NOT NULL,
    execution_id TEXT,
    level TEXT NOT NULL DEFAULT 'info',
    message TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (sandbox_id) REFERENCES sandbox_instances(sandbox_id)
);

CREATE INDEX IF NOT EXISTS idx_sandbox_logs_sandbox ON sandbox_logs(sandbox_id);

CREATE TABLE IF NOT EXISTS sandbox_metrics (
    metric_id TEXT PRIMARY KEY,
    sandbox_id TEXT NOT NULL,
    execution_id TEXT,
    cpu_used REAL NOT NULL DEFAULT 0,
    memory_used_mb INTEGER NOT NULL DEFAULT 0,
    disk_io_mb REAL NOT NULL DEFAULT 0,
    network_bytes INTEGER NOT NULL DEFAULT 0,
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (sandbox_id) REFERENCES sandbox_instances(sandbox_id)
);

CREATE INDEX IF NOT EXISTS idx_sandbox_metrics_sandbox ON sandbox_metrics(sandbox_id);
