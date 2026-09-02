import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

const auth = JSON.parse(readFileSync('.auth.json', 'utf8')) as { baseURL: string; username: string; password: string };

async function login(page: Page) {
  await page.goto('/');
  await page.fill('#uname', auth.username);
  await page.fill('#pwd', auth.password);
  await page.click('button:has-text("Sign In")');
  // The top nav (with Sign Out) renders on both desktop and mobile once in.
  await expect(page.getByRole('button', { name: 'Sign Out' })).toBeVisible({ timeout: 15_000 });
}

// navTo clicks a sidebar section, opening the mobile menu first on small screens.
async function navTo(page: Page, label: string) {
  const toggle = page.locator('.mobile-toggle');
  const mobile = await toggle.isVisible().catch(() => false);
  if (mobile) {
    await toggle.click();
    // The mobile drawer has its own nav-btns; the desktop sidebar is hidden.
    await page.locator('.mobile-drawer .nav-btn', { hasText: label }).click();
  } else {
    await page.locator('.sidebar .nav-btn', { hasText: label }).click();
  }
}

test('panel UI boots — login works and the shell renders', async ({ page }) => {
  await login(page);
  await expect(page.locator('.top-nav')).toBeVisible();
});

test('Domains: no-domain banner is bilingual and a domain can be added', async ({ page, request }) => {
  await login(page);
  const token = await page.evaluate(() => localStorage.getItem('forge_token'));
  const h = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
  // Start from a clean no-domain state (the two projects share one panel).
  const existing = await (await request.get(`${auth.baseURL}/api/admin/domains`, { headers: h })).json();
  for (const d of existing) await request.delete(`${auth.baseURL}/api/admin/domains/${d.id}?force=true`, { headers: h });

  await navTo(page, 'Domains');
  await expect(page.getByText(/No domain configured/i)).toBeVisible();
  await expect(page.locator('[lang="fa"]')).toBeVisible(); // Farsi guidance present
  await page.getByPlaceholder('vpn.example.com').fill('e2e.example.com');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('cell', { name: 'e2e.example.com' })).toBeVisible({ timeout: 10_000 });

  // Clean up so the other project starts from the no-domain state too.
  const after = await (await request.get(`${auth.baseURL}/api/admin/domains`, { headers: h })).json();
  for (const d of after) await request.delete(`${auth.baseURL}/api/admin/domains/${d.id}?force=true`, { headers: h });
});

test('BUG-4: inbound edit lifecycle persists and undo restores', async ({ page, request }) => {
  await login(page);
  const token = await page.evaluate(() => localStorage.getItem('forge_token'));
  const h = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

  const create = await request.post(`${auth.baseURL}/api/admin/inbounds`, {
    headers: h,
    data: { protocol: 'vless', port: 24443, remark: 'e2e-edit', transport: { network: 'tcp' }, security: { type: 'reality' } },
  });
  expect(create.ok()).toBeTruthy();
  const { id } = await create.json();

  const edit = await request.put(`${auth.baseURL}/api/admin/inbounds/${id}`, {
    headers: h,
    data: { protocol: 'vless', port: 24443, remark: 'e2e-edited', transport: { network: 'tcp' }, security: { type: 'reality' } },
  });
  expect(edit.ok()).toBeTruthy();
  let list = await (await request.get(`${auth.baseURL}/api/admin/inbounds`, { headers: h })).json();
  expect(list.find((i: any) => i.id === id)?.remark).toBe('e2e-edited');

  const undo = await request.post(`${auth.baseURL}/api/admin/inbounds/${id}/undo`, { headers: h });
  expect(undo.ok()).toBeTruthy();
  list = await (await request.get(`${auth.baseURL}/api/admin/inbounds`, { headers: h })).json();
  expect(list.find((i: any) => i.id === id)?.remark).toBe('e2e-edit');

  // clean up so a re-run starts fresh
  await request.delete(`${auth.baseURL}/api/admin/inbounds/${id}`, { headers: h });
});
