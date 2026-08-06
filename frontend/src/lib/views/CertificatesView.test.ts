import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import CertificatesView from './CertificatesView.svelte';

describe('CertificatesView Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('loads TLS status and updates domain address', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string, opts?: any) => {
      if (opts?.method === 'POST' && url.includes('/panel-address')) {
        return Promise.resolve({ ok: true, json: async () => ({ domain: 'new.example.com' }) });
      }
      if (url.includes('/panel-address')) {
        return Promise.resolve({ ok: true, json: async () => ({ domain: 'panel.example.com' }) });
      }
      if (url.includes('/admin/certs')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            domain: 'panel.example.com',
            status: 'valid',
            issuer: 'LetsEncrypt',
            auto_tls: true
          })
        });
      }
      return Promise.resolve({ ok: true, json: async () => ({}) });
    }));

    render(CertificatesView);

    const input = await screen.findByDisplayValue('panel.example.com');
    await fireEvent.input(input, { target: { value: 'new.example.com' } });

    const saveBtn = screen.getByText('Save Domain');
    await fireEvent.click(saveBtn);

    expect(fetch).toHaveBeenCalledWith('/api/admin/panel-address', expect.objectContaining({ method: 'POST' }));
  });

  it('runs DNS check (resolved and unresolved) and renews ACME certificate', async () => {
    let checkCount = 0;
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string, opts?: any) => {
      if (url.includes('/dns-check')) {
        checkCount++;
        if (checkCount === 1) {
          return Promise.resolve({ ok: true, json: async () => ({ resolved: true, ip: '1.1.1.1' }) });
        }
        return Promise.resolve({ ok: true, json: async () => ({ resolved: false }) });
      }
      if (url.includes('/cert/renew') && opts?.method === 'POST') {
        return Promise.resolve({ ok: true, json: async () => ({ status: 'requested' }) });
      }
      if (url.includes('/admin/certs')) {
        return Promise.resolve({ ok: true, json: async () => ({ domain: 'panel.example.com', status: 'valid' }) });
      }
      return Promise.resolve({
        ok: true,
        json: async () => ({ domain: 'panel.example.com' })
      });
    }));

    render(CertificatesView);

    const checkBtn = await screen.findByText('Check DNS');
    await fireEvent.click(checkBtn);
    await fireEvent.click(checkBtn);

    const renewBtn = await screen.findByText('Force ACME Renew');
    await fireEvent.click(renewBtn);

    expect(fetch).toHaveBeenCalledWith('/api/admin/panel-address/cert/renew', expect.objectContaining({ method: 'POST' }));
  });

  it('handles empty domain early return in checkDns', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ domain: '' })
    }));

    render(CertificatesView);

    const checkBtn = await screen.findByText('Check DNS');
    await fireEvent.click(checkBtn);

    // Should not call dns-check endpoint when domain is empty
    expect(fetch).not.toHaveBeenCalledWith(expect.stringContaining('/dns-check'), expect.anything());
  });

  it('handles error paths in loadData, updateDomain, checkDns, renewCert, importCert', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Network Error')));

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
