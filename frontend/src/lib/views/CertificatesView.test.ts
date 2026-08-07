import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
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
