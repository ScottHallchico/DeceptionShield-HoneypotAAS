import { expect, test } from "@playwright/test";

test("operator can sign in, watch live events arrive, and open an attacker's detail panel", async ({
  page,
}) => {
  await page.goto("/login");

  // Demo credentials: leaving both fields blank signs in as the seeded demo operator.
  await page.getByRole("button", { name: /sign in/i }).click();

  await expect(page).toHaveURL(/\/dashboard$/);

  // The mock backend streams seeded events on an interval — wait for at least
  // one row to land in the live feed rather than asserting on a fixed count.
  const firstRow = page.getByTestId("feed-row").first();
  await expect(firstRow).toBeVisible({ timeout: 15_000 });

  await firstRow.click();

  await expect(page.getByTestId("attacker-panel")).toBeVisible();
});

test("unauthenticated visitors are redirected away from the console", async ({ page }) => {
  await page.goto("/dashboard");
  await expect(page).toHaveURL(/\/login/);
});
