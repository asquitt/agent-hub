# AgentHub ERD (D03)

## Entity Relationship Overview
The data model prioritizes relational integrity for core registry operations while supporting high-volume telemetry and capability search.

```mermaid
erDiagram
    USERS ||--o{ ORGANIZATIONS : owns
    ORGANIZATIONS ||--o{ ORGANIZATION_MEMBERS : has
    USERS ||--o{ ORGANIZATION_MEMBERS : joins
    USERS ||--o{ NAMESPACES : controls
    ORGANIZATIONS ||--o{ NAMESPACES : controls
    NAMESPACES ||--o{ AGENTS : contains
    AGENTS ||--o{ AGENT_VERSIONS : versions
    AGENT_VERSIONS ||--o{ CAPABILITY_CATALOG : exposes
    AGENT_VERSIONS ||--o{ EVAL_RUNS : evaluated_by
    AGENTS ||--o| REPUTATION_SCORES : scored_as
    AGENTS ||--o{ DELEGATION_RECORDS : requester
    AGENTS ||--o{ DELEGATION_RECORDS : delegate
    ORGANIZATIONS ||--o{ BILLING_EVENTS : billed
    AGENTS ||--o{ BILLING_EVENTS : generates

    USERS {
      uuid id PK
      text email UNIQUE
      text display_name
      text status
    }
    NAMESPACES {
      uuid id PK
      text namespace UNIQUE
      uuid owner_user_id FK
      uuid owner_org_id FK
    }
    AGENTS {
      uuid id PK
      uuid namespace_id FK
      text slug
      uuid latest_version_id FK
      text status
    }
    AGENT_VERSIONS {
      uuid id PK
      uuid agent_id FK
      text version
      text manifest_s3_uri
      text manifest_sha256
    }
    CAPABILITY_CATALOG {
      uuid id PK
      uuid agent_version_id FK
      text capability_id
      text capability_name
      vector embedding
      numeric trust_score
    }
    EVAL_RUNS {
      uuid id PK
      uuid agent_version_id FK
      text tier
      text status
      numeric pass_rate
    }
    REPUTATION_SCORES {
      uuid id PK
      uuid agent_id FK
      numeric composite_trust
      timestamptz computed_at
    }
    DELEGATION_RECORDS {
      uuid id PK
      uuid requester_agent_id FK
      uuid delegate_agent_id FK
      text status
      timestamptz created_at PK
    }
    BILLING_EVENTS {
      uuid id PK
      uuid org_id FK
      uuid agent_id FK
      numeric amount_usd
      timestamptz occurred_at
    }
```

## Storage Strategy by Domain
- PostgreSQL 16: source of truth for users/orgs/agents/versions/capabilities/evals/trust/billing.
- pgvector (in Postgres): capability embeddings for semantic matching without separate vector infra in early phases.
- S3/R2: manifest artifacts, eval traces, and large immutable payload storage.
- Optional analytics store (later): ClickHouse or Athena for billion-event log analytics.

## pgvector Index Design
- Vector column: `capability_catalog.embedding VECTOR(1536)`
- Primary ANN index: `hnsw (embedding vector_cosine_ops)` with `m=16`, `ef_construction=128`
- Hybrid retrieval path:
  1. Policy filters (trust, permissions, cost, latency)
  2. Text prefilter (`pg_trgm` on `search_text`)
  3. Vector similarity refinement

## Data Retention and Archival Policies
- `api_events`: 90 days hot retention in Postgres; aggregate rollups retained long-term.
- `delegation_records`: partitioned by time; partitions older than 180 days exported and archived.
- `eval_runs.trace_s3_uri`: 365 days in S3 Standard, then Glacier archive tier.
- `billing_events`: 7 years retained for financial/audit compliance.
- Deleted/suspended user PII: 30-day legal hold then hard delete.

## Scale Notes (Year 1 Targets)
- Agents: 10K-100K
- Agent versions: 500K-5M
- Capabilities: 50K-500K
- Eval runs: 1M-10M
- Delegation records: 10M-100M/year
