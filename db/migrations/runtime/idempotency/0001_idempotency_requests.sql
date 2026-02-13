CREATE TABLE IF NOT EXISTS idempotency_requests (
    tenant_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    method TEXT NOT NULL,
    route TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    http_status INTEGER,
    content_type TEXT,
    headers_json TEXT,
    response_body_b64 TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (tenant_id, actor, method, route, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_idempotency_requests_lookup
ON idempotency_requests(actor, method, route, idempotency_key);
