# AgentHub Cost Model (D03)

## Assumptions
- Region: us-east-1 equivalent pricing.
- Traffic profile scales from prototype through early production.
- Postgres + pgvector is the default search/index stack through early growth.
- Object storage used for manifests/eval traces; compute burst handled by autoscaling.

## Monthly Cost Projection by Scale Tier

| Year | Tier | Active Agents | Monthly Min (USD) | Monthly Max (USD) | Annual Min (USD) | Annual Max (USD) |
|---|---|---:|---:|---:|---:|---:|
| 0 | Prototype | 0-50 | 0 | 60 | 0 | 720 |
| 1 | MVP | 100-1,000 | 50 | 500 | 600 | 6,000 |
| 2 | Growth | 1,000-5,000 | 500 | 2,000 | 6,000 | 24,000 |
| 3 | Early Scale | 5,000-10,000 | 2,000 | 5,000 | 24,000 | 60,000 |

## Cost Envelope by Service Component

| Component | Year 1 (USD/mo) | Year 2 (USD/mo) | Year 3 (USD/mo) | Notes |
|---|---:|---:|---:|---|
| API compute (FastAPI containers) | 20-120 | 120-450 | 450-1,200 | Horizontal scaling by request + job queue depth |
| Postgres + pgvector | 0-80 | 120-600 | 600-1,600 | Start serverless/free tier; move to managed HA cluster |
| Object storage (S3/R2) | 5-35 | 35-180 | 180-650 | Eval traces dominate storage growth |
| Redis cache | 0-25 | 25-120 | 120-300 | Rate limiting + hot search caching |
| Monitoring/alerting | 0-40 | 40-180 | 180-500 | Grafana + Sentry initially |
| Sandbox runtime | 25-200 | 200-500 | 500-1,200 | Pay-per-use model execution |
| CI/CD + misc ops | 0-20 | 20-80 | 80-250 | Includes build and artifact transfer |

## Cost Optimization Strategy
- Keep vector search in Postgres using pgvector until recall/latency requires dedicated vector infra.
- Use lifecycle policies to move cold eval traces to archive tiers.
- Use read replicas only after sustained P95 read latency pressure.
- Separate ingestion and query workloads to prevent noisy-neighbor effects.
- Enforce budget guardrails at invocation and monthly aggregation levels.

## Unit Economics Watch Metrics
- Cost per capability invocation (p50/p95)
- Delegation success-adjusted cost
- Gross margin per design partner
- Cost variance by workflow class
- Storage growth rate vs. retention policy effectiveness

## Spreadsheet Artifact
See `cost-model.csv` for machine-readable projections from Year 0 to Year 3.
