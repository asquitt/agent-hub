const { expect } = require("@playwright/test");

function suffix(length = 10) {
  return Math.random().toString(16).slice(2, 2 + length);
}

function uniqueId(prefix) {
  return `${prefix}-${Date.now()}-${suffix(8)}`;
}

function manifestTemplate(agentSlug, version) {
  return {
    schema_version: "0.1",
    identity: {
      id: agentSlug,
      name: `Playwright ${agentSlug}`,
      version,
      description: "Playwright e2e test agent manifest.",
      owner: "agenthub-e2e",
      type: "orchestrator",
    },
    capabilities: [
      {
        id: "plan-pipeline",
        name: "Plan Pipeline",
        category: "orchestration",
        description: "Plans agent execution pipelines for deterministic workflows.",
        input_schema: {
          type: "object",
          properties: {
            task: {
              type: "string",
            },
          },
          required: ["task"],
          additionalProperties: false,
        },
        output_schema: {
          type: "object",
          properties: {
            recommended_agents: {
              type: "array",
              items: {
                type: "string",
              },
            },
          },
          required: ["recommended_agents"],
          additionalProperties: false,
        },
        protocols: ["MCP", "A2A"],
        permissions: ["capabilities.search"],
        idempotency_key_required: false,
        side_effect_level: "none",
      },
    ],
    interfaces: [
      {
        name: "mcp",
        protocol: "MCP",
        endpoint: "https://example.local/mcp/playwright-agent",
        auth: "signed_jwt",
        privileged: false,
      },
    ],
    trust: {
      minimum_trust_score: 0.75,
      allowed_trust_sources: ["first_party"],
      policy: {
        injection_protection: "strict",
        pii_handling: "deny",
        data_retention_days: 7,
        high_risk_approval_required: true,
      },
      budget_guardrails: {
        soft_alert_pct: 80,
        reauthorization_pct: 100,
        hard_stop_pct: 120,
      },
      credential_policy: {
        short_lived_credentials: true,
        max_ttl_minutes: 60,
      },
    },
    runtime: {
      execution_mode: "deterministic_workflow",
      sandbox: "container",
      max_retries: 2,
      timeout_seconds: 30,
      idempotency_required: true,
      replay_safe: true,
      observability: {
        log_privileged_actions: true,
        emit_cost_metrics: true,
        emit_latency_metrics: true,
      },
    },
  };
}

async function api(request, method, path, opts = {}) {
  const httpMethod = method.toUpperCase();
  const headers = {
    ...(opts.headers || {}),
  };
  if (opts.apiKey) {
    headers["X-API-Key"] = opts.apiKey;
  }
  if (["POST", "PUT", "PATCH", "DELETE"].includes(httpMethod) && !headers["Idempotency-Key"]) {
    headers["Idempotency-Key"] = uniqueId(`idem-${httpMethod.toLowerCase()}`);
  }
  if (opts.data !== undefined && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  const response = await request.fetch(path, {
    method: httpMethod,
    headers,
    data: opts.data,
    failOnStatusCode: false,
  });
  const status = response.status();
  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (_error) {
      payload = { raw: text };
    }
  }

  return {
    response,
    status,
    payload,
    headers: response.headers(),
  };
}

async function expectStatus(result, expectedStatus, context) {
  expect(result.status, `${context} -> ${JSON.stringify(result.payload)}`).toBe(expectedStatus);
  return result.payload;
}

async function seedAgent(request, options = {}) {
  const agentSuffix = suffix(8);
  const namespacePrefix = options.namespacePrefix || "pw";
  const namespace = options.namespace || `@${namespacePrefix}${agentSuffix}`;
  const agentSlug = options.agentSlug || `playwright-agent-${agentSuffix}`;
  const version = options.version || "0.1.0";
  const manifest = manifestTemplate(agentSlug, version);

  const created = await api(request, "POST", "/v1/agents", {
    apiKey: options.apiKey || "dev-owner-key",
    data: {
      namespace,
      manifest,
    },
    headers: options.headers,
  });
  const payload = await expectStatus(created, 200, "seed agent register");
  return {
    namespace,
    agentSlug,
    agentId: payload.id,
    manifest,
    payload,
  };
}

async function updateAgentVersion(request, agentId, agentSlug, version, options = {}) {
  const updated = await api(request, "PUT", `/v1/agents/${encodeURIComponent(agentId)}`, {
    apiKey: options.apiKey || "dev-owner-key",
    data: {
      manifest: manifestTemplate(agentSlug, version),
    },
    headers: options.headers,
  });
  return expectStatus(updated, 200, "update agent version");
}

async function seedAgentWithVersionPair(request, options = {}) {
  const seeded = await seedAgent(request, {
    ...options,
    version: options.baseVersion || "1.0.0",
  });
  await updateAgentVersion(
    request,
    seeded.agentId,
    seeded.agentSlug,
    options.targetVersion || "1.1.0",
    options
  );
  return seeded;
}

async function createDelegation(request, agentId, options = {}) {
  const result = await api(request, "POST", "/v1/delegations", {
    apiKey: options.apiKey || "dev-owner-key",
    data: {
      requester_agent_id: agentId,
      delegate_agent_id: agentId,
      task_spec: options.taskSpec || "Playwright operator delegation check",
      estimated_cost_usd: options.estimatedCostUsd || 2.0,
      max_budget_usd: options.maxBudgetUsd || 5.0,
      simulated_actual_cost_usd: options.simulatedActualCostUsd || 1.8,
    },
  });
  const payload = await expectStatus(result, 200, "create delegation");
  return payload;
}

module.exports = {
  api,
  expectStatus,
  manifestTemplate,
  seedAgent,
  seedAgentWithVersionPair,
  updateAgentVersion,
  createDelegation,
  uniqueId,
};
