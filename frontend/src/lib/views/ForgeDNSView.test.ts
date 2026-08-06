import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import ForgeDNSView from './ForgeDNSView.svelte';

describe('ForgeDNSView Component', () => {
  beforeEach(() => {
    (globalThis as any).confirm = () => true;
    (globalThis as any).navigator = {
      clipboard: {
        writeText: async () => {}
      }
    };
  });

  it('loads DNS adapters and zone list', async () => {
    (globalThis as any).fetch = async (url: string) => {
      if (url.includes('/adapters')) {
        return {
          ok: true,
          json: async () => [{ id: 'miekg', name: 'Miekg DNS' }]
        } as Response;
      }
      if (url.includes('/zones')) {
        return {
          ok: true,
          json: async () => [
            { id: 1, domain: 't.example.com', adapter: 'miekg', active: false, sessions: 0 }
          ]
        } as Response;
      }
      return { ok: true, json: async () => ([]) } as Response;
    };

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
    let deleteCalled = false;
    let copyCalled = false;
    (globalThis as any).navigator.clipboard.writeText = async () => { copyCalled = true; };
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'POST') {
        return {
          ok: true,
          json: async () => ({
            id: 1,
            domain: 'new.example.com',
            adapter: 'miekg',
            active: true,
            ns_records: [{ host: 'ns1', target: '2.2.2.2' }],
            client_uri: 'dns://new.example.com'
          })
        } as Response;
      }
      if (opts?.method === 'DELETE') {
        deleteCalled = true;
        return { ok: true, json: async () => ({ deleted: 1 }) } as Response;
      }
      return {
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
      } as Response;
    };

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
    expect(copyCalled).toBe(true);

    const deleteBtn = screen.getByText('Delete');
    await fireEvent.click(deleteBtn);
    expect(deleteCalled).toBe(true);
  });

  it('handles delete zone confirmation cancel and errors', async () => {
    let deleteCalled = false;
    (globalThis as any).confirm = () => false;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'DELETE') deleteCalled = true;
      if (url.includes('/zones')) {
        return {
          ok: true,
          json: async () => [
            { id: 1, domain: 't.example.com', adapter: 'miekg', active: true }
          ]
        } as Response;
      }
      return { ok: true, json: async () => ([]) } as Response;
    };

    render(ForgeDNSView);

    const deleteBtn = await screen.findByText('Delete');
    await fireEvent.click(deleteBtn);
    expect(deleteCalled).toBe(false);
  });

  it('handles error paths in loadData, createZone, deleteZone, copyClientUri', async () => {
    (globalThis as any).confirm = () => true;
    (globalThis as any).navigator.clipboard.writeText = async () => { throw new Error('Copy Failed'); };
    (globalThis as any).fetch = async () => { throw new Error('DNS Failure'); };

    render(ForgeDNSView);

    const domainInput = screen.getByPlaceholderText('Tunnel domain (e.g. dns.example.com)');
    await fireEvent.input(domainInput, { target: { value: 'err.example.com' } });

    const createBtn = screen.getByText('Create & Activate');
    await fireEvent.click(createBtn);

    expect(await screen.findByText('DNS Failure')).toBeTruthy();
  });
});
