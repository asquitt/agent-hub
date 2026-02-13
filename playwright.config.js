const path = require("node:path");
const { defineConfig } = require("@playwright/test");

const runtimeRoot = path.join(__dirname, ".tmp", "playwright-runtime");
const runtimePath = (name) => path.join(runtimeRoot, name);

module.exports = defineConfig({
  testDir: path.join(__dirname, "e2e", "playwright"),
  timeout: 120_000,
  expect: {
    timeout: 15_000,
  },
  workers: 1,
  retries: 0,
  reporter: [["list"], ["html", { outputFolder: "playwright-report", open: "never" }]],
  use: {
    baseURL: "http://127.0.0.1:8011",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  webServer: {
    command: "mkdir -p .tmp/playwright-runtime && python3 -m uvicorn src.api.main:app --host 127.0.0.1 --port 8011",
    url: "http://127.0.0.1:8011/healthz",
    timeout: 120_000,
    reuseExistingServer: false,
    env: {
      PYTHONUNBUFFERED: "1",
      AGENTHUB_ACCESS_ENFORCEMENT_MODE: "enforce",
      AGENTHUB_API_KEYS_JSON: JSON.stringify({
        "dev-owner-key": "owner-dev",
        "partner-owner-key": "owner-partner",
        "platform-owner-key": "owner-platform",
      }),
      AGENTHUB_AUTH_TOKEN_SECRET: "playwright-e2e-secret",
      AGENTHUB_REGISTRY_DB_PATH: runtimePath("registry.db"),
      AGENTHUB_DELEGATION_DB_PATH: runtimePath("delegation.db"),
      AGENTHUB_IDEMPOTENCY_DB_PATH: runtimePath("idempotency.db"),
      AGENTHUB_BILLING_DB_PATH: runtimePath("billing.db"),
      AGENTHUB_COST_DB_PATH: runtimePath("billing.db"),
      AGENTHUB_COST_EVENTS_PATH: runtimePath("cost-events.json"),
      AGENTHUB_MARKETPLACE_LISTINGS_PATH: runtimePath("marketplace-listings.json"),
      AGENTHUB_MARKETPLACE_CONTRACTS_PATH: runtimePath("marketplace-contracts.json"),
      AGENTHUB_MARKETPLACE_DISPUTES_PATH: runtimePath("marketplace-disputes.json"),
      AGENTHUB_MARKETPLACE_PAYOUTS_PATH: runtimePath("marketplace-payouts.json"),
      AGENTHUB_PROCUREMENT_POLICY_PACKS_PATH: runtimePath("proc-policy-packs.json"),
      AGENTHUB_PROCUREMENT_APPROVALS_PATH: runtimePath("proc-approvals.json"),
      AGENTHUB_PROCUREMENT_EXCEPTIONS_PATH: runtimePath("proc-exceptions.json"),
      AGENTHUB_PROCUREMENT_AUDIT_PATH: runtimePath("proc-audit.json"),
      AGENTHUB_EVAL_RESULTS_PATH: runtimePath("eval-results.json"),
      AGENTHUB_TRUST_USAGE_EVENTS_PATH: runtimePath("trust-usage-events.json"),
      AGENTHUB_TRUST_REVIEWS_PATH: runtimePath("trust-reviews.json"),
      AGENTHUB_TRUST_SECURITY_AUDITS_PATH: runtimePath("trust-security-audits.json"),
      AGENTHUB_TRUST_INCIDENTS_PATH: runtimePath("trust-incidents.json"),
      AGENTHUB_TRUST_PUBLISHER_PROFILES_PATH: runtimePath("trust-publisher-profiles.json"),
      AGENTHUB_TRUST_SCORES_PATH: runtimePath("trust-scores.json"),
      AGENTHUB_TRUST_INTERACTION_GRAPH_PATH: runtimePath("trust-interaction-graph.json"),
      AGENTHUB_DELEGATION_RECORDS_PATH: runtimePath("delegation-records.json"),
      AGENTHUB_DELEGATION_BALANCES_PATH: runtimePath("delegation-balances.json"),
      AGENTHUB_DEVHUB_DB_PATH: runtimePath("devhub.db"),
      AGENTHUB_COMPLIANCE_EVIDENCE_PATH: runtimePath("compliance-evidence.json"),
      AGENTHUB_FEDERATION_AUDIT_PATH: runtimePath("federation-audit.json"),
    },
  },
});
