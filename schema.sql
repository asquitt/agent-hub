-- AgentHub D03: PostgreSQL schema (with pgvector + pg_trgm)
-- Target: metadata, versions, capabilities, evals, trust, delegation, billing, and operational telemetry.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Accounts and organizations
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email CITEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  api_key_hash TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','deleted')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  owner_user_id UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS organization_members (
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('owner','admin','maintainer','viewer')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (org_id, user_id)
);

CREATE TABLE IF NOT EXISTS namespaces (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  namespace TEXT UNIQUE NOT NULL,
  owner_user_id UUID REFERENCES users(id),
  owner_org_id UUID REFERENCES organizations(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK ((owner_user_id IS NOT NULL) <> (owner_org_id IS NOT NULL))
);

-- Agents and version lineage
CREATE TABLE IF NOT EXISTS agents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  namespace_id UUID NOT NULL REFERENCES namespaces(id),
  slug TEXT NOT NULL,
  latest_version_id UUID,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','deprecated','archived')),
  created_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (namespace_id, slug)
);

CREATE TABLE IF NOT EXISTS agent_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  version TEXT NOT NULL,
  manifest_s3_uri TEXT NOT NULL,
  manifest_sha256 TEXT NOT NULL,
  changelog TEXT,
  is_deprecated BOOLEAN NOT NULL DEFAULT FALSE,
  published_by UUID NOT NULL REFERENCES users(id),
  published_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (agent_id, version)
);

ALTER TABLE agents
  ADD CONSTRAINT fk_agents_latest_version
  FOREIGN KEY (latest_version_id) REFERENCES agent_versions(id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE IF NOT EXISTS capability_catalog (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_version_id UUID NOT NULL REFERENCES agent_versions(id) ON DELETE CASCADE,
  capability_id TEXT NOT NULL,
  capability_name TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  protocols TEXT[] NOT NULL,
  permissions TEXT[] NOT NULL DEFAULT '{}',
  input_schema JSONB NOT NULL,
  output_schema JSONB NOT NULL,
  compatibility_hash TEXT NOT NULL,
  trust_score NUMERIC(4,3) NOT NULL DEFAULT 0.000 CHECK (trust_score >= 0 AND trust_score <= 1),
  estimated_cost_usd NUMERIC(10,6) NOT NULL DEFAULT 0,
  p95_latency_ms INTEGER NOT NULL DEFAULT 0,
  usage_30d BIGINT NOT NULL DEFAULT 0,
  freshness_days INTEGER NOT NULL DEFAULT 0,
  embedding VECTOR(1536),
  search_text TEXT GENERATED ALWAYS AS (
    lower(capability_name || ' ' || description || ' ' || array_to_string(protocols, ' '))
  ) STORED,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (agent_version_id, capability_id)
);

-- Eval, trust, delegation, and billing
CREATE TABLE IF NOT EXISTS eval_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_version_id UUID NOT NULL REFERENCES agent_versions(id) ON DELETE CASCADE,
  tier TEXT NOT NULL CHECK (tier IN ('tier1_contract','tier2_accuracy','tier3_safety')),
  suite_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued','running','passed','failed','errored')),
  pass_rate NUMERIC(5,2),
  latency_p95_ms INTEGER,
  total_cost_usd NUMERIC(10,6),
  trace_s3_uri TEXT,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reputation_scores (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  eval_signal NUMERIC(5,4) NOT NULL,
  usage_signal NUMERIC(5,4) NOT NULL,
  publisher_signal NUMERIC(5,4) NOT NULL,
  community_signal NUMERIC(5,4) NOT NULL,
  security_signal NUMERIC(5,4) NOT NULL,
  freshness_signal NUMERIC(5,4) NOT NULL,
  incident_penalty NUMERIC(5,4) NOT NULL DEFAULT 0,
  composite_trust NUMERIC(5,4) NOT NULL,
  computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (agent_id)
);

CREATE TABLE IF NOT EXISTS delegation_records (
  id UUID NOT NULL DEFAULT gen_random_uuid(),
  requester_agent_id UUID REFERENCES agents(id),
  delegate_agent_id UUID REFERENCES agents(id),
  request_idempotency_key TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('accepted','rejected','failed','completed')),
  trust_snapshot NUMERIC(5,4) NOT NULL,
  estimated_cost_usd NUMERIC(10,6) NOT NULL,
  actual_cost_usd NUMERIC(10,6),
  latency_ms INTEGER,
  input_hash TEXT NOT NULL,
  output_hash TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- Seed partition; production creates monthly partitions via scheduler.
CREATE TABLE IF NOT EXISTS delegation_records_2026q1
  PARTITION OF delegation_records
  FOR VALUES FROM ('2026-01-01') TO ('2026-04-01');

CREATE TABLE IF NOT EXISTS billing_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES organizations(id),
  agent_id UUID REFERENCES agents(id),
  event_type TEXT NOT NULL CHECK (event_type IN ('invoke','delegation','storage','egress','credit_adjustment')),
  amount_usd NUMERIC(10,6) NOT NULL,
  quantity NUMERIC(14,4) NOT NULL DEFAULT 1,
  currency TEXT NOT NULL DEFAULT 'USD',
  metadata JSONB NOT NULL DEFAULT '{}',
  occurred_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_type TEXT NOT NULL CHECK (actor_type IN ('user','agent','system')),
  actor_id TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  method TEXT NOT NULL,
  status_code INTEGER NOT NULL,
  latency_ms INTEGER NOT NULL,
  cost_usd NUMERIC(10,6),
  request_bytes INTEGER,
  response_bytes INTEGER,
  input_hash TEXT,
  output_hash TEXT,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Key indexes for relational + vector + text retrieval performance
CREATE INDEX IF NOT EXISTS idx_agents_namespace_slug ON agents(namespace_id, slug);
CREATE INDEX IF NOT EXISTS idx_agent_versions_agent_published ON agent_versions(agent_id, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_capability_catalog_agent_version ON capability_catalog(agent_version_id);
CREATE INDEX IF NOT EXISTS idx_capability_catalog_protocols_gin ON capability_catalog USING GIN (protocols);
CREATE INDEX IF NOT EXISTS idx_capability_catalog_permissions_gin ON capability_catalog USING GIN (permissions);
CREATE INDEX IF NOT EXISTS idx_capability_catalog_search_text_trgm ON capability_catalog USING GIN (search_text gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_capability_catalog_trust ON capability_catalog(trust_score DESC);
CREATE INDEX IF NOT EXISTS idx_eval_runs_agent_tier ON eval_runs(agent_version_id, tier, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_billing_events_org_time ON billing_events(org_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_events_endpoint_time ON api_events(endpoint, occurred_at DESC);

-- pgvector index design for capability retrieval
CREATE INDEX IF NOT EXISTS idx_capability_embedding_hnsw
  ON capability_catalog USING hnsw (embedding vector_cosine_ops)
  WITH (m = 16, ef_construction = 128);

-- Operational materialized view for trust leaderboard
CREATE MATERIALIZED VIEW IF NOT EXISTS trust_leaderboard AS
SELECT
  a.id AS agent_id,
  n.namespace || '/' || a.slug AS agent_ref,
  r.composite_trust,
  r.computed_at
FROM agents a
JOIN namespaces n ON n.id = a.namespace_id
JOIN reputation_scores r ON r.agent_id = a.id
WHERE a.status = 'active';

CREATE INDEX IF NOT EXISTS idx_trust_leaderboard_score ON trust_leaderboard(composite_trust DESC);
