-- D03 migration: retention and maintenance routines (template)

-- Suggested monthly partition management (to be automated via cron/job runner)
-- CREATE TABLE delegation_records_2026q2 PARTITION OF delegation_records
--   FOR VALUES FROM ('2026-04-01') TO ('2026-07-01');

-- Suggested retention jobs (implemented via pg_cron or external scheduler):
-- 1) Raw API events retained 90 days in primary DB.
-- 2) Aggregated daily metrics retained indefinitely in analytics store.
-- 3) Eval trace artifacts retained in S3 for 365 days, then Glacier archive.
-- 4) Deleted/suspended user PII hard-deleted after 30-day legal hold.

-- Refresh trust leaderboard every 15 minutes.
-- REFRESH MATERIALIZED VIEW CONCURRENTLY trust_leaderboard;
