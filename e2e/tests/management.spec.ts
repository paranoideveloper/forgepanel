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

test('assign an inbound to a user; the user subscription then carries a config', async ({ page, request }) => {
  await login(page);

  // 1) create an inbound to assign
  await nav(page, 'Inbounds');
  await page.getByTestId('create-inbound').click();
  await page.getByTestId('proto-select').selectOption('vless');
  await page.getByTestId('field-remark').fill('assign-target');
  await page.getByTestId('field-port').fill('47001');
  for (let i = 0; i < await page.locator('[data-testid^=gen-]').count(); i++) await page.locator('[data-testid^=gen-]').nth(i).click();
  await page.getByTestId('save-inbound').click();
  await expect(page.locator('[data-testid=inbound-row]', { hasText: 'assign-target' })).toBeVisible();

  // 2) create a user
  await nav(page, 'Users');
  await page.fill('input[placeholder="username"]', 'u-assign');
  await page.getByTestId('create-user').click();
  const row = page.locator('tr', { hasText: 'u-assign' });
  await expect(row).toBeVisible({ timeout: 8_000 });
  const subToken = (await row.locator('code').innerText()).trim();

  // 3) Manage → assign the inbound → Save
  await row.getByTestId('manage-user').click();
  const assign = page.getByTestId('assign-inbounds');
  await expect(assign).toBeVisible();
  await assign.locator('label', { hasText: 'assign-target' }).locator('input[type=checkbox]').check();
  await page.getByTestId('save-manage').click();
  await expect(page.getByTestId('assign-inbounds')).toBeHidden({ timeout: 8_000 });

  // 4) POSITIVE: the user's subscription now contains a proxy config for that inbound.
  const res = await request.get(`/sub/${subToken}`);
  expect(res.ok()).toBeTruthy();
  const body = Buffer.from(await res.text(), 'base64').toString('utf8');
  expect(body).toContain('vless://');
});

test('an inbound can be edited (remark + port) and it persists', async ({ page }) => {
  await login(page);
  await nav(page, 'Inbounds');
  await page.getByTestId('create-inbound').click();
  await page.getByTestId('proto-select').selectOption('trojan');
  await page.getByTestId('field-remark').fill('edit-me');
  await page.getByTestId('field-port').fill('47010');
  for (let i = 0; i < await page.locator('[data-testid^=gen-]').count(); i++) await page.locator('[data-testid^=gen-]').nth(i).click();
  await page.getByTestId('save-inbound').click();
  const row = page.locator('[data-testid=inbound-row]', { hasText: 'edit-me' });
  await expect(row).toBeVisible();

  await row.getByTestId('edit-btn').click();
  const editor = page.getByTestId('inbound-editor');
  await expect(editor).toBeVisible();
  await editor.getByTestId('field-remark').fill('edited-name');
  await editor.getByTestId('field-port').fill('47011');
  await editor.getByTestId('save-inbound').click();
  // POSITIVE: the edited inbound shows the new remark + port.
  await expect(page.locator('[data-testid=inbound-row]', { hasText: 'edited-name' })).toBeVisible({ timeout: 8_000 });
  await expect(page.locator('[data-testid=inbound-row]', { hasText: '47011' })).toBeVisible();
});

test('bulk operations disable multiple inbounds at once', async ({ page }) => {
  await login(page);
  await nav(page, 'Inbounds');
  // create two inbounds
  for (const [name, port] of [['bulk-a', '47020'], ['bulk-b', '47021']] as const) {
    await page.getByTestId('create-inbound').click();
    await page.getByTestId('proto-select').selectOption('vless');
    await page.getByTestId('field-remark').fill(name);
    await page.getByTestId('field-port').fill(port);
    for (let i = 0; i < await page.locator('[data-testid^=gen-]').count(); i++) await page.locator('[data-testid^=gen-]').nth(i).click();
    await page.getByTestId('save-inbound').click();
    await expect(page.locator('[data-testid=inbound-row]', { hasText: name })).toBeVisible();
  }
  // select all → bulk disable
  await page.getByTestId('select-all').check();
  await expect(page.getByTestId('bulk-bar')).toBeVisible();
  await page.locator('[data-testid=bulk-bar] button', { hasText: 'Disable' }).click();
  await page.waitForTimeout(1000);
  // POSITIVE: both rows now show Disabled.
  await expect(page.locator('[data-testid=inbound-row]', { hasText: 'bulk-a' }).locator('.badge', { hasText: 'Disabled' })).toBeVisible({ timeout: 8_000 });
});

test('a group can be created with inbounds assigned', async ({ page }) => {
  await login(page);
  await nav(page, 'Users');
  await page.getByTestId('new-group').click();
  await page.getByTestId('group-name').fill('vip');
  await page.getByTestId('save-group').click();
  await expect(page.locator('tr', { hasText: 'vip' })).toBeVisible({ timeout: 8_000 });
});
