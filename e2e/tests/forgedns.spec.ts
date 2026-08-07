import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

const auth = JSON.parse(readFileSync('.auth.json', 'utf8')) as { baseURL: string; username: string; password: string };

async function login(page: Page) {
  await page.goto('/');
  await page.fill('#uname', auth.username);
  await page.fill('#pwd', auth.password);
  await page.click('button:has-text("Sign In")');
  await expect(page.getByRole('button', { name: 'Sign Out' })).toBeVisible({ timeout: 15_000 });
}
async function nav(page: Page, label: string) {
  const t = page.locator('.mobile-toggle');
  if (await t.isVisible().catch(() => false)) { await t.click(); await page.locator('.mobile-drawer .nav-btn', { hasText: label }).click(); }
  else await page.locator('.sidebar .nav-btn', { hasText: label }).click();
}

// Regression for "ForgeDNS shows nothing": the adapter dropdown was fed a bare
// []string so every <option> was blank, and create/list/setup read the wrong
// JSON keys. This drives the real flow against the built, embedded binary.
test('ForgeDNS: adapter dropdown is populated and a zone can be created end-to-end', async ({ page }, testInfo) => {
  // Desktop + mobile projects share one backend, so use a project-unique zone
  // name — a duplicate zone would 409 on the second project.
  const zoneName = `t-${testInfo.project.name}.forgedns.example`;
  await login(page);
  await nav(page, 'ForgeDNS');

  // POSITIVE: the adapter <select> has real, non-empty option labels.
  const select = page.getByTestId('adapter-select');
  await expect(select).toBeVisible();
  const optionLabels = await select.locator('option').allInnerTexts();
  expect(optionLabels.length).toBeGreaterThan(0);
  expect(optionLabels.every((t) => t.trim().length > 0)).toBeTruthy();

  // Create a zone — the request must carry {zone,adapter}, and the row must appear.
  await page.getByTestId('zone-domain').fill(zoneName);
  await page.getByTestId('create-zone').click();

  const row = page.locator('[data-testid=zone-row]', { hasText: zoneName });
  await expect(row).toBeVisible({ timeout: 10_000 });
  await expect(row.locator('.badge', { hasText: 'Active' })).toBeVisible();

  // POSITIVE: the setup panel opens with real delegation records + a client config.
  await expect(page.getByTestId('setup-panel')).toBeVisible({ timeout: 10_000 });
  await expect(page.getByTestId('ns-record').first()).toBeVisible({ timeout: 10_000 });
  await expect(page.getByTestId('client-config')).toBeVisible({ timeout: 10_000 });

  await page.screenshot({ path: 'test-results/forgedns.png', fullPage: true });
});
