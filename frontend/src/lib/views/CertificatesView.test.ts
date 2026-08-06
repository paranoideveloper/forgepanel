import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import CertificatesView from './CertificatesView.svelte';

describe('CertificatesView Component', () => {
  beforeEach(() => {});

  it('loads TLS status and updates domain address', async () => {
    let postCalled = false;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'POST' && url.includes('/panel-address')) {
        postCalled = true;
        return { ok: true, json: async () => ({ domain: 'new.example.com' }) } as Response;
      }
      if (url.includes('/panel-address')) {
        return { ok: true, json: async () => ({ domain: 'panel.example.com' }) } as Response;
      }
      if (url.includes('/admin/certs')) {
        return {
          ok: true,
          json: async () => ({
            domain: 'panel.example.com',
            status: 'valid',
            issuer: 'LetsEncrypt',
            auto_tls: true
          })
        } as Response;
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
        return { ok: true, json: async () => ({ resolved: true, ip: '1.1.1.1' }) } as Response;
      }
      if (url.includes('/cert/renew') && opts?.method === 'POST') {
        renewCalled = true;
        return { ok: true, json: async () => ({ status: 'requested' }) } as Response;
      }
      if (url.includes('/admin/certs')) {
        return { ok: true, json: async () => ({ domain: 'panel.example.com', status: 'valid' }) } as Response;
      }
      return { ok: true, json: async () => ({ domain: 'panel.example.com' }) } as Response;
    };

    render(CertificatesView);

    const checkBtn = await screen.findByText('Check DNS');
    await fireEvent.click(checkBtn);

    const renewBtn = await screen.findByText('Force ACME Renew');
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
      return { ok: true, json: async () => ({ domain: 'panel.example.com' }) } as Response;
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
