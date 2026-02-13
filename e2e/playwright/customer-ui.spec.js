const { test, expect } = require("@playwright/test");

test.describe("S58 Customer UI E2E", () => {
  test("customer journey console runs the full demo flow", async ({ page }) => {
    await page.setExtraHTTPHeaders({ "X-API-Key": "dev-owner-key" });
    await page.goto("/customer");
    await page.setExtraHTTPHeaders({});

    await expect(page.getByRole("heading", { name: "Customer Journey Console" })).toBeVisible();
    await expect(page.locator("#sellerKey")).toHaveValue("");
    await expect(page.locator("#buyerKey")).toHaveValue("");
    await expect(page.locator("#adminKey")).toHaveValue("");
    const runButton = page.getByRole("button", { name: "Run Full Demo" });
    await expect(runButton).toBeDisabled();

    await page.locator("#sellerKey").fill("dev-owner-key");
    await page.locator("#buyerKey").fill("partner-owner-key");
    await page.locator("#adminKey").fill("platform-owner-key");
    await page.locator("#unitPrice").fill("0.75");
    await page.locator("#units").fill("4");
    await expect(runButton).toBeEnabled();

    await runButton.click();
    await expect(page.locator("#status")).toContainText("Demo completed successfully", { timeout: 120_000 });

    const outputText = await page.locator("#output").textContent();
    const payload = JSON.parse(outputText || "{}");
    expect(payload.summary).toBeTruthy();
    expect(payload.summary.agent_id).toContain("@cust");
    expect(payload.summary.contract_id).toBeTruthy();
    expect(payload.summary.reconcile_matched).toBe(true);
    expect(payload.summary.compare_risk_level).toBe("low");
  });

  test.use({ viewport: { width: 390, height: 844 } });
  test("customer page is usable on mobile viewport", async ({ page }) => {
    await page.setExtraHTTPHeaders({ "X-API-Key": "dev-owner-key" });
    await page.goto("/customer");
    await page.setExtraHTTPHeaders({});
    await expect(page.getByRole("button", { name: "Run Full Demo" })).toBeVisible();
    await expect(page.locator("#sellerKey")).toBeVisible();
    await expect(page.locator("#units")).toBeVisible();
  });
});
