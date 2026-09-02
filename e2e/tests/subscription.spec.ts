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

// The subscription-defaults card drives the BPB/Nova-style routing + TLS-fragment
// features. Prove it renders, persists to the backend, and that the /sub endpoint
// then emits Iran routing rules by default (the config-level behaviour is
// exhaustively checked against the real cores in the Go tests).
test('subscription defaults card persists routing + fragment', async ({ page, request }) => {
  await login(page);
  await nav(page, 'Users');

  const card = page.getByTestId('sub-settings');
  await expect(card).toBeVisible();

  await page.getByTestId('routing-preset').selectOption('full');
  const frag = page.getByTestId('fragment-toggle');
  if (!(await frag.isChecked())) await frag.check();
  await page.getByTestId('save-sub-settings').click();

  // POSITIVE: navigate away and back; the saved values are reloaded from the API.
  await nav(page, 'Overview');
  await nav(page, 'Users');
  await expect(page.getByTestId('routing-preset')).toHaveValue('full', { timeout: 8_000 });
  await expect(page.getByTestId('fragment-toggle')).toBeChecked();

  // POSITIVE: the /sub endpoint honours the operator default — a sing-box config
  // (routing rules emit even before any node is assigned) carries the Iran set.
  const sb = await (await request.get('/sub/anytoken-unknown/sing-box')).text();
  expect(sb).toContain('geosite-ir');
});
