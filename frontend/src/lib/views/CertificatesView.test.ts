import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import CertificatesView from './CertificatesView.svelte';

// The panel-address endpoint is the single source of truth for domain + cert
// status; every mock returns its full shape (including the nested cert object).
function panelAddress(overrides: Record<string, unknown> = {}) {
  return {
    domain: 'panel.example.com',
    port: 2053,
    admin_path: '/panel/abc',
    bind_address: '0.0.0.0',
    public_url: 'https://panel.example.com:2053/panel/abc',
    https_enabled: true,
    server_ipv4: '203.0.113.10',
    server_ipv6: '',
    cert: { available: true, issuer: "Let's Encrypt", not_after: '2026-11-05T20:03:01Z', days_remaining: 90, acme: { enabled: true, provider: 'letsencrypt', email: '', challenge: 'http-01', staging: false } },
    ...overrides
  };
}

describe('CertificatesView Component', () => {
  beforeEach(() => {});

  it('loads TLS status and updates domain address', async () => {
    let postCalled = false;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'POST' && url.includes('/panel-address')) {
        postCalled = true;
        return { ok: true, json: async () => ({ restart_required: false, public_url: 'https://new.example.com:2053/panel/abc' }) } as Response;
      }
      if (url.includes('/panel-address')) {
        return { ok: true, json: async () => panelAddress() } as Response;
      }
      return { ok: true, json: async () => ({}) } as Response;
    };

    render(CertificatesView);

    const input = await screen.findByDisplayValue('panel.example.com');
    await fireEvent.input(input, { target: { value: 'new.example.com' } });

    const saveBtn = screen.getByText('Save Domain');
    await fireEvent.click(saveBtn);

    expect(postCalled).toBe(true);
  });

  it('runs DNS check and renews ACME certificate', async () => {
    let renewCalled = false;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (url.includes('/dns-check')) {
        return { ok: true, json: async () => ({ domain: 'panel.example.com', resolves: true, a: ['203.0.113.10'], points_here: true, server_ipv4: '203.0.113.10' }) } as Response;
      }
      if (url.includes('/cert/renew') && opts?.method === 'POST') {
        renewCalled = true;
        return { ok: true, json: async () => ({ ok: true }) } as Response;
      }
      return { ok: true, json: async () => panelAddress() } as Response;
    };

    render(CertificatesView);

    // Wait for onMount → loadData to populate the domain before checking DNS
    // (checkDns is a no-op while the domain input is still empty).
    await screen.findByDisplayValue('panel.example.com');
    const checkBtn = await screen.findByText('Check DNS');
    await fireEvent.click(checkBtn);
    // POSITIVE: a resolving domain that points here shows the success line.
    expect(await screen.findByTestId('dns-result')).toBeTruthy();

    const renewBtn = await screen.findByText('Force ACME Issue / Renew');
    await fireEvent.click(renewBtn);

    expect(renewCalled).toBe(true);
  });

  it('validates and imports custom TLS certificate', async () => {
    let importCalled = false;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (url.includes('/certs/import') && opts?.method === 'POST') {
        importCalled = true;
        return { ok: true, json: async () => ({ status: 'imported' }) } as Response;
      }
      return { ok: true, json: async () => panelAddress() } as Response;
    };

    render(CertificatesView);

    const importBtn = await screen.findByText('Import Custom Certificate');
    await fireEvent.click(importBtn);
    expect(await screen.findByText('Both Certificate PEM and Private Key PEM are required')).toBeTruthy();

    const certArea = screen.getByPlaceholderText('-----BEGIN CERTIFICATE-----');
    const keyArea = screen.getByPlaceholderText('-----BEGIN PRIVATE KEY-----');

    await fireEvent.input(certArea, { target: { value: 'CERT_DATA' } });
    await fireEvent.input(keyArea, { target: { value: 'KEY_DATA' } });

    await fireEvent.click(importBtn);
    expect(importCalled).toBe(true);
  });

  it('handles error paths in loadData, updateDomain, checkDns, renewCert, importCert', async () => {
    (globalThis as any).fetch = async () => { throw new Error('Network Error'); };

    render(CertificatesView);

    const refreshBtn = screen.getByText('Refresh');
    await fireEvent.click(refreshBtn);

    const input = screen.getByPlaceholderText('panel.example.com');
    await fireEvent.input(input, { target: { value: 'err.example.com' } });

    const saveBtn = screen.getByText('Save Domain');
    await fireEvent.click(saveBtn);

    const checkBtn = screen.getByText('Check DNS');
    await fireEvent.click(checkBtn);

    const importBtn = screen.getByText('Import Custom Certificate');
    const certArea = screen.getByPlaceholderText('-----BEGIN CERTIFICATE-----');
    const keyArea = screen.getByPlaceholderText('-----BEGIN PRIVATE KEY-----');

    await fireEvent.input(certArea, { target: { value: 'CERT' } });
    await fireEvent.input(keyArea, { target: { value: 'KEY' } });
    await fireEvent.click(importBtn);

    expect(await screen.findByText('Network Error')).toBeTruthy();
  });
});

// The panel-address surface was write-one-field / read-none. POST accepts
// domain, port, bind_address, https_enabled, acme_email and verify_dns, and this
// view posted {domain}. GET returns port, bind_address, admin_path,
// https_enabled and server_ipv6, and rendered none of them. So the panel's own
// port and bind address could only be changed by hand-editing panel.json and
// restarting — on the one screen whose entire subject is where the panel lives.
describe('CertificatesView panel listener', () => {
  function api(onPost?: (body: any) => any, addrOverrides: Record<string, unknown> = {}) {
    const posts: any[] = [];
    const gets: string[] = [];
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      const path = String(url);
      if (opts?.method === 'POST') {
        const body = opts.body ? JSON.parse(opts.body) : {};
        posts.push(body);
        if (onPost) return { ok: true, json: async () => onPost(body) } as Response;
        return { ok: true, json: async () => ({ restart_required: true, public_url: 'x' }) } as Response;
      }
      gets.push(path);
      if (path.includes('/panel-address/port-check')) {
        const port = Number(new URL(path, 'http://x').searchParams.get('port'));
        return { ok: true, json: async () => ({ port, available: port !== 80, current: port === 2053 }) } as Response;
      }
      if (path.includes('/panel-address')) return { ok: true, json: async () => panelAddress(addrOverrides) } as Response;
      return { ok: true, json: async () => ({}) } as Response;
    };
    return { posts, gets };
  }

  it('renders the listener fields the endpoint has always returned', async () => {
    api();
    render(CertificatesView);
    const port = (await screen.findByTestId('port-input')) as HTMLInputElement;
    expect(port.value).toBe('2053');
    expect((screen.getByTestId('bind-input') as HTMLInputElement).value).toBe('0.0.0.0');
    expect((screen.getByTestId('https-toggle') as HTMLInputElement).checked).toBe(true);
    expect(screen.getByTestId('admin-path').textContent).toContain('/panel/abc');
  });

  it('pre-flights the port before the panel is moved onto it', async () => {
    const { gets } = api();
    render(CertificatesView);
    const port = (await screen.findByTestId('port-input')) as HTMLInputElement;
    await fireEvent.input(port, { target: { value: '80' } });
    await fireEvent.click(screen.getByTestId('check-port'));
    const result = await screen.findByTestId('port-result');
    expect(result.textContent).toContain('already in use');
    expect(gets.some((g) => g.includes('/panel-address/port-check?port=80'))).toBe(true);
  });

  it('distinguishes the port the panel is already on from a free one', async () => {
    api();
    render(CertificatesView);
    await screen.findByTestId('port-input');
    await fireEvent.click(screen.getByTestId('check-port'));
    expect((await screen.findByTestId('port-result')).textContent).toContain('already on');
  });

  it('sends every field the endpoint accepts, not just the domain', async () => {
    const { posts } = api();
    render(CertificatesView);
    const port = (await screen.findByTestId('port-input')) as HTMLInputElement;
    await fireEvent.input(port, { target: { value: '8443' } });
    await fireEvent.input(screen.getByTestId('bind-input'), { target: { value: '127.0.0.1' } });
    await fireEvent.click(screen.getByTestId('save-address'));
    await waitFor(() => expect(posts.length).toBeGreaterThan(0));
    expect(posts[0]).toMatchObject({
      domain: 'panel.example.com', port: 8443, bind_address: '127.0.0.1', https_enabled: true
    });
  });

  it('refuses a port outside the range before it becomes a bare 400', async () => {
    api();
    render(CertificatesView);
    const port = (await screen.findByTestId('port-input')) as HTMLInputElement;
    await fireEvent.input(port, { target: { value: '70000' } });
    expect(await screen.findByTestId('port-invalid')).toBeTruthy();
    expect((screen.getByTestId('save-address') as HTMLButtonElement).disabled).toBe(true);
  });

  it('refuses a bind address that is not an IP', async () => {
    api();
    render(CertificatesView);
    await screen.findByTestId('bind-input');
    await fireEvent.input(screen.getByTestId('bind-input'), { target: { value: 'localhost' } });
    expect(await screen.findByTestId('bind-invalid')).toBeTruthy();
  });

  it('explains the domain rule rather than letting the server answer with a 400', async () => {
    api();
    render(CertificatesView);
    // Wait for the load first. The domain input renders before the fetch
    // resolves, and typing into it early is overwritten when loadData lands —
    // the test would then be asserting against the SERVER's domain, not the
    // typed one, and would pass or fail for the wrong reason.
    await screen.findByTestId('port-input');
    const domain = screen.getByTestId('domain-input') as HTMLInputElement;
    await fireEvent.input(domain, { target: { value: 'not a domain' } });
    expect(await screen.findByTestId('domain-invalid')).toBeTruthy();
  });

  it('says HTTPS needs a domain instead of posting a request that cannot succeed', async () => {
    // A panel on a bare IP with HTTPS still switched on: the state a save would
    // be rejected from, reached without touching anything.
    api(undefined, { domain: '' });
    render(CertificatesView);
    await screen.findByTestId('port-input');
    expect((screen.getByTestId('https-toggle') as HTMLInputElement).checked).toBe(true);
    expect(await screen.findByTestId('https-needs-domain')).toBeTruthy();
    expect((screen.getByTestId('save-address') as HTMLButtonElement).disabled).toBe(true);
  });
});
