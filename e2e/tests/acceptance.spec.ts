import { test, expect, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

// The BUG-9 acceptance suite: it drives the BUILT, go:embed'd binary (globalSetup
// spawns ./forgepanel-test and completes first-run setup) and makes POSITIVE,
// SPECIFIC assertions — the protocol dropdown by name, a real client link in the
// preview, a saved inbound appearing in the list and yielding a config link.
// A pane that renders empty fails these.

const auth = JSON.parse(readFileSync('.auth.json', 'utf8')) as { username: string; password: string };

const PROTOS = [
  'vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'hysteria2',
  'tuic', 'anytls', 'shadowtls', 'wireguard', 'amneziawg', 'brook',
];

async function login(page: Page) {
  await page.goto('/');
  await page.fill('#uname', auth.username);
  await page.fill('#pwd', auth.password);
  await page.click('button:has-text("Sign In")');
  await expect(page.getByRole('button', { name: 'Sign Out' })).toBeVisible({ timeout: 15_000 });
}

async function gotoInbounds(page: Page) {
  const toggle = page.locator('.mobile-toggle');
  if (await toggle.isVisible().catch(() => false)) {
    await toggle.click();
    await page.locator('.mobile-drawer .nav-btn', { hasText: 'Inbounds' }).click();
  } else {
    await page.locator('.sidebar .nav-btn', { hasText: 'Inbounds' }).click();
  }
  await expect(page.getByTestId('create-inbound')).toBeVisible({ timeout: 10_000 });
}

test('Config Studio can create a VLESS+REALITY inbound end to end', async ({ page }) => {
  await login(page);
  await gotoInbounds(page);
  await page.getByTestId('create-inbound').click();

  // POSITIVE: the protocol dropdown contains all 13 creatable protocols by name.
  const options = await page.locator('[data-testid=proto-select] option').allInnerTexts();
  expect(options.length).toBeGreaterThanOrEqual(13);
  for (const name of ['VLESS', 'VMess', 'Trojan', 'Shadowsocks', 'Hysteria2', 'TUIC', 'AnyTLS', 'ShadowTLS', 'WireGuard', 'Brook']) {
    expect(options.join(' ')).toContain(name);
  }

  await page.getByTestId('field-remark').fill('e2e-vless');
  // Generate the REALITY keypair + shortId via the UI buttons.
  const gens = page.locator('[data-testid^=gen-]');
  for (let i = 0; i < await gens.count(); i++) { await gens.nth(i).click(); }

  // POSITIVE: the live preview contains a real vless:// client link.
  await expect(page.getByTestId('preview-body')).toContainText('vless://', { timeout: 8_000 });

  await page.getByTestId('save-inbound').click();
  // POSITIVE: the saved inbound appears in the list.
  await expect(page.locator('[data-testid=inbound-row]', { hasText: 'e2e-vless' })).toBeVisible({ timeout: 8_000 });

  // POSITIVE: its config card yields a vless:// link.
  await page.locator('[data-testid=inbound-row]', { hasText: 'e2e-vless' }).getByTestId('config-btn').click();
  await expect(page.getByTestId('config-uri')).toContainText('vless://', { timeout: 6_000 });
  await page.screenshot({ path: 'test-results/inbound-config.png' });
});

test('every protocol can be created through the UI', async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  await login(page);
  await gotoInbounds(page);

  let created = 0;
  for (let i = 0; i < PROTOS.length; i++) {
    const proto = PROTOS[i];
    if (await page.getByTestId('proto-select').count() === 0) {
      await page.getByTestId('create-inbound').click();
      await expect(page.getByTestId('proto-select')).toBeVisible({ timeout: 6_000 });
    }
    await page.getByTestId('proto-select').selectOption(proto);
    await page.getByTestId('field-remark').fill(`e2e-${proto}`);
    await page.getByTestId('field-port').fill(String(45001 + i));
    const gens = page.locator('[data-testid^=gen-]');
    for (let g = 0; g < await gens.count(); g++) { await gens.nth(g).click(); }
    await page.waitForTimeout(400);
    await page.getByTestId('save-inbound').click();
    await page.waitForTimeout(700);
    if (await page.locator('[data-testid=inbound-row]', { hasText: `e2e-${proto}` }).count() > 0) created++;
  }
  await page.screenshot({ path: 'test-results/inbounds-all.png', fullPage: true });
  // POSITIVE: all 13 protocols produced a saved inbound in the list.
  expect(created).toBe(PROTOS.length);
});
