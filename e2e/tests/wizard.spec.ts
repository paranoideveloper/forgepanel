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

// The guided setup wizard walks a new operator through the whole flow end-to-end.
// This drives it against the built, embedded binary: skip domain → create a REALITY
// inbound → create a user → reach the share step with a real subscription link.
test('setup wizard: domain → inbound → user → share', async ({ page, request }, testInfo) => {
  // Desktop + mobile share one backend, so the username must be project-unique.
  const uname = `wizard-${testInfo.project.name}`;
  await login(page);
  await nav(page, 'Setup Wizard');

  // Step 1 — skip the domain (no real DNS on a throwaway host).
  await page.getByTestId('wiz-skip-domain').click();

  // Step 2 — one-click REALITY inbound.
  await page.getByTestId('wiz-create-inbound').click();
  await expect(page.getByTestId('wiz-next-user')).toBeEnabled({ timeout: 10_000 });
  await page.getByTestId('wiz-next-user').click();

  // Step 3 — first user.
  await page.getByTestId('wiz-username').fill(uname);
  await page.getByTestId('wiz-create-user').click();

  // Step 4 — share: a real subscription link is shown and its config works.
  const copy = page.getByTestId('wiz-copy-sub');
  await expect(copy).toBeVisible({ timeout: 10_000 });
  const link = (await page.locator('.linkrow code').innerText()).trim();
  expect(link).toContain('/sub/');
  const token = link.split('/sub/')[1];

  // POSITIVE: the user's subscription actually carries the REALITY inbound config.
  const body = Buffer.from(await (await request.get(`/sub/${token}?raw=1`)).text(), 'base64').toString('utf8');
  expect(body).toContain('vless://');
  expect(body).toContain('reality');

  await page.screenshot({ path: 'test-results/wizard.png', fullPage: true });
});
