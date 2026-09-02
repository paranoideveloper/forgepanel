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

// Regression for the v1.5.4 cert-page fix: the view used to read the wrong JSON
// keys (resolved/ip and the imported-cert list) and so ALWAYS showed "DNS failed
// to resolve" and "Self-Signed / Indefinite". These are positive assertions that
// it now reads the real panel-address fields (cert.available + resolves/points_here).
test('certificates page reads real cert status and DNS-check fields', async ({ page }) => {
  await login(page);
  await nav(page, 'Certificates & TLS');

  // Saving a domain (no verify) succeeds and — per v1.5.4 — implies HTTPS/ACME.
  await page.getByTestId('domain-input').fill('example.com');
  await page.getByTestId('save-domain').click();

  // POSITIVE: the cert-status card renders a real verdict. With a domain set but
  // no issued cert on this throwaway host, that is "Pending issuance" — proving
  // the card reads cert.available rather than defaulting to a static string.
  const status = page.getByTestId('cert-status');
  await expect(status).toBeVisible({ timeout: 8_000 });
  await expect(status).toHaveText(/Pending issuance|Trusted \(ACME\)/);

  // POSITIVE: the DNS check renders a result parsed from resolves/a/points_here.
  // example.com resolves but does not point at this host → the "points elsewhere"
  // line, which is only reachable if resolves===true is read correctly.
  await page.getByTestId('check-dns').click();
  const dns = page.getByTestId('dns-result');
  await expect(dns).toBeVisible({ timeout: 12_000 });
  await expect(dns).toHaveText(/resolves to/i);

  await page.screenshot({ path: 'test-results/certificates.png', fullPage: true });
});
