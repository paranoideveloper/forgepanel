import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import ForgeDNSView from './ForgeDNSView.svelte';

describe('ForgeDNSView Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.stubGlobal('confirm', () => true);
    vi.stubGlobal('navigator', {
      clipboard: {
        writeText: vi.fn().mockResolvedValue(undefined)
      }
    });
  });

  it('loads DNS adapters and zone list (including stopped zones)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.includes('/adapters')) {
        return Promise.resolve({
          ok: true,
          json: async () => [{ id: 'miekg', name: 'Miekg DNS' }]
        });
      }
      if (url.includes('/zones')) {
        return Promise.resolve({
          ok: true,
          json: async () => [
            { id: 1, domain: 't.example.com', adapter: 'miekg', active: false, sessions: 0 }
          ]
        });
      }
      return Promise.resolve({ ok: true, json: async () => ([]) });
    }));

    render(ForgeDNSView);

    expect(await screen.findByText('t.example.com')).toBeTruthy();
    expect(screen.getByText('miekg')).toBeTruthy();
    expect(screen.getByText('Stopped')).toBeTruthy();
  });

  it('validates tunnel creation input', async () => {
    render(ForgeDNSView);
    const createBtn = screen.getByText('Create & Activate');
    await fireEvent.click(createBtn);
    expect(await screen.findByText('Tunnel domain is required')).toBeTruthy();
  });

  it('creates zone, views setup details, copies URI, and deletes selected zone', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string, opts?: any) => {
      if (opts?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            id: 1,
            domain: 'new.example.com',
            adapter: 'miekg',
            active: true,
            ns_records: [{ host: 'ns1', target: '2.2.2.2' }],
            client_uri: 'dns://new.example.com'
          })
        });
      }
      if (opts?.method === 'DELETE') {
        return Promise.resolve({ ok: true, json: async () => ({ deleted: 1 }) });
      }
      return Promise.resolve({
        ok: true,
        json: async () => [
          {
            id: 1,
            domain: 't.example.com',
            adapter: 'miekg',
            active: true,
            ns_records: [{ host: 'ns1', target: '1.1.1.1' }],
            client_uri: 'dns://t.example.com'
          }
        ]
      });
    }));

    render(ForgeDNSView);

    const domainInput = screen.getByPlaceholderText('Tunnel domain (e.g. dns.example.com)');
    await fireEvent.input(domainInput, { target: { value: 'new.example.com' } });

    const createBtn = screen.getByText('Create & Activate');
    await fireEvent.click(createBtn);

    const setupBtn = await screen.findByText('Setup Info');
    await fireEvent.click(setupBtn);

    expect(screen.getByText('Delegation & Setup — t.example.com')).toBeTruthy();

    const copyBtn = screen.getByText('Copy URI');
    await fireEvent.click(copyBtn);
    expect(navigator.clipboard.writeText).toHaveBeenCalled();

    const deleteBtn = screen.getByText('Delete');
    await fireEvent.click(deleteBtn);
    expect(fetch).toHaveBeenCalledWith('/api/admin/forgedns/zones/1', expect.objectContaining({ method: 'DELETE' }));
  });

  it('handles delete zone confirmation cancel and errors', async () => {
    vi.stubGlobal('confirm', () => false);
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.includes('/zones')) {
        return Promise.resolve({
          ok: true,
          json: async () => [
            { id: 1, domain: 't.example.com', adapter: 'miekg', active: true }
          ]
        });
      }
      return Promise.resolve({ ok: true, json: async () => ([]) });
    }));

    render(ForgeDNSView);

    const deleteBtn = await screen.findByText('Delete');
    await fireEvent.click(deleteBtn);
    expect(fetch).not.toHaveBeenCalledWith(expect.stringContaining('/zones/1'), expect.objectContaining({ method: 'DELETE' }));
  });

  it('handles error paths in loadData, createZone, deleteZone, copyClientUri', async () => {
    vi.stubGlobal('confirm', () => true);
    vi.stubGlobal('navigator', {
      clipboard: {
        writeText: vi.fn().mockRejectedValue(new Error('Copy Failed'))
      }
    });
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('DNS Failure')));

    render(ForgeDNSView);

    const domainInput = screen.getByPlaceholderText('Tunnel domain (e.g. dns.example.com)');
    await fireEvent.input(domainInput, { target: { value: 'err.example.com' } });

    const createBtn = screen.getByText('Create & Activate');
    await fireEvent.click(createBtn);

    expect(await screen.findByText('DNS Failure')).toBeTruthy();
  });
});
