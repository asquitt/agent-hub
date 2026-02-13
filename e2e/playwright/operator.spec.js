const { test, expect } = require("@playwright/test");
const { api, createDelegation, seedAgent, seedAgentWithVersionPair, expectStatus } = require("./support/agenthub");

test.describe("S55 Operator and Versioning E2E", () => {
  test("operator dashboard and replay journey with role boundaries", async ({ page, request }) => {
    const seeded = await seedAgent(request, { namespacePrefix: "ops" });
    const delegation = await createDelegation(request, seeded.agentId, {
      taskSpec: "Operator timeline replay coverage",
      estimatedCostUsd: 2.0,
      maxBudgetUsd: 5.0,
      simulatedActualCostUsd: 1.8,
    });

    await page.goto("/operator");
    await page.getByLabel("API Key").fill("partner-owner-key");
    await page.getByLabel("Operator Role").selectOption("viewer");
    await page.getByLabel("Agent ID").fill(seeded.agentId);
    await page.getByLabel("Search Query").fill("plan pipeline");

    await page.getByRole("button", { name: "Load Dashboard" }).click();
    await expect(page.locator("#status")).toContainText("Loaded dashboard as viewer");
    await expect(page.locator("#replayDelegationId")).toHaveValue(delegation.delegation_id);
    await expect(page.locator("#timelineOut")).toContainText("lifecycle_stage");

    await page.getByRole("button", { name: "Load Replay" }).click();
    await expect(page.locator("#status")).toContainText(`Loaded replay for ${delegation.delegation_id}`);
    await expect(page.locator("#replayOut")).toContainText(delegation.delegation_id);

    await expect(page.getByRole("button", { name: "Admin Refresh" })).toBeDisabled();
    await page.getByLabel("Operator Role").selectOption("admin");
    await expect(page.getByRole("button", { name: "Admin Refresh" })).toBeEnabled();
    await page.getByRole("button", { name: "Admin Refresh" }).click();
    await expect(page.locator("#status")).toContainText("Refresh failed");

    await page.getByLabel("API Key").fill("dev-owner-key");
    await page.getByRole("button", { name: "Admin Refresh" }).click();
    await expect(page.locator("#status")).toContainText("Refresh status: refreshed (admin)");
  });

  test("version compare console loads latest pair and compares", async ({ page, request }) => {
    const seeded = await seedAgentWithVersionPair(request, {
      namespacePrefix: "cmp",
      baseVersion: "1.0.0",
      targetVersion: "1.1.0",
    });

    await page.goto("/operator/versioning");
    await page.locator("#agentId").fill(seeded.agentId);

    await page.getByRole("button", { name: "Load Latest Pair" }).click();
    await expect(page.locator("#status")).toContainText("Loaded version pair 1.0.0 -> 1.1.0");
    await expect(page.locator("#baseVersion")).toHaveValue("1.0.0");
    await expect(page.locator("#targetVersion")).toHaveValue("1.1.0");

    await page.getByRole("button", { name: "Compare Versions" }).click();
    await expect(page.locator("#status")).toContainText("Compared 1.0.0 -> 1.1.0");
    await expect(page.locator("#output")).toContainText('"compatibility"');
  });

  test("operator refresh scope works for bearer tokens", async ({ request }) => {
    const tokenResponse = await api(request, "POST", "/v1/auth/tokens", {
      apiKey: "dev-owner-key",
      data: { scopes: ["operator.refresh"], ttl_seconds: 900 },
    });
    const tokenPayload = await expectStatus(tokenResponse, 200, "issue operator token");

    const refresh = await api(request, "POST", "/v1/operator/refresh", {
      headers: {
        Authorization: `Bearer ${tokenPayload.access_token}`,
        "X-Operator-Role": "admin",
      },
    });
    const refreshPayload = await expectStatus(refresh, 200, "refresh with bearer token");
    expect(refreshPayload.status).toBe("refreshed");
  });
});
