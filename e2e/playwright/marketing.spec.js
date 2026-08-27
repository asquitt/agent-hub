const { test, expect } = require("@playwright/test");

test.describe("S69 Marketing Site", () => {
  test("marketing home renders hero and CTAs", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Know Which Agent Can Act. Control What Happens Next." })).toBeVisible();
    await expect(page.getByRole("link", { name: "Open Operator Console" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Explore API" })).toBeVisible();
    await expect(page.locator("body")).toContainText("Agent Identity + Discovery Control Plane");
    await expect(page.locator("body")).toContainText("Production readiness is not claimed");
  });

  test.use({ viewport: { width: 390, height: 844 } });
  test("marketing home is usable on mobile", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("link", { name: "Open Operator Console" })).toBeVisible();
    await expect(page.getByRole("link", { name: "API Docs" })).toBeVisible();
    await expect(page.locator("body")).toContainText("Current evidence boundary");
  });
});
