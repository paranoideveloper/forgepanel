import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import ForgeDNSView from './ForgeDNSView.svelte';

// These mocks mirror the REAL backend contract (verified against the Go handlers):
//   /adapters → [{id,name,description}]   /zones → [{id,zone,adapter,enabled,...}]
//   POST /zones expects {zone,adapter} and returns the created zone
//   /zones/:id/bundle → {zone,ns_records:[{type,name,value}],client_config_toml,...}
const ADAPTERS = [{ id: 'cottendns', name: 'CottenDNS (A)', description: 'A-record downstream.' }];
const BUNDLE = {
  zone: 'new.example.com', adapter: 'cottendns', ns_host: 'ns.new.example.com',
  ns_records: [{ type: 'A', name: 'ns.new.example.com', value: '203.0.113.10' }, { type: 'NS', name: 'new.example.com', value: 'ns.new.example.com' }],
  cloudflare_warning: 'Disable the orange cloud.', client_config_toml: 'server = "new.example.com"\nkey = "secret"', socks5: '127.0.0.1:1080', steps: ['Delegate NS', 'Run client']
};

describe('ForgeDNSView Component', () => {
  beforeEach(() => {
    (globalThis as any).confirm = () => true;
    (globalThis as any).navigator = { clipboard: { writeText: async () => {} } };
  });

  it('loads DNS adapters and zone list using the real fields (zone/enabled)', async () => {
    (globalThis as any).fetch = async (url: string) => {
      if (url.includes('/adapters')) return { ok: true, json: async () => ADAPTERS } as Response;
      if (url.includes('/zones')) return { ok: true, json: async () => [{ id: 1, zone: 't.example.com', adapter: 'cottendns', enabled: false, bind_host: '0.0.0.0', bind_port: 53 }] } as Response;
      return { ok: true, json: async () => [] } as Response;
    };
    render(ForgeDNSView);
    expect(await screen.findByText('t.example.com')).toBeTruthy();
    expect(screen.getByText('cottendns')).toBeTruthy();
    expect(screen.getByText('Stopped')).toBeTruthy();
    // The adapter dropdown has a real, non-empty label (regression for the blank dropdown).
    expect(screen.getByRole('option', { name: 'CottenDNS (A)' })).toBeTruthy();
  });

  it('validates tunnel creation input', async () => {
    (globalThis as any).fetch = async () => ({ ok: true, json: async () => [] } as Response);
    render(ForgeDNSView);
    const createBtn = screen.getByText('Create & Activate');
    await fireEvent.click(createBtn);
    expect(await screen.findByText('Tunnel domain is required')).toBeTruthy();
  });

  it('creates a zone (sends {zone,adapter}), shows the delegation bundle, copies config, deletes', async () => {
    let postBody: any = null; let deleteCalled = false; let copyCalled = false;
    (globalThis as any).navigator.clipboard.writeText = async () => { copyCalled = true; };
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'POST') { postBody = JSON.parse(opts.body); return { ok: true, json: async () => ({ id: 1, zone: 'new.example.com', adapter: 'cottendns', enabled: true }) } as Response; }
      if (opts?.method === 'DELETE') { deleteCalled = true; return { ok: true, json: async () => ({ deleted: 1 }) } as Response; }
      if (url.includes('/bundle')) return { ok: true, json: async () => BUNDLE } as Response;
      if (url.includes('/adapters')) return { ok: true, json: async () => ADAPTERS } as Response;
      return { ok: true, json: async () => [{ id: 1, zone: 't.example.com', adapter: 'cottendns', enabled: true }] } as Response;
    };
    render(ForgeDNSView);

    // Wait for the adapter list to land before submitting. The view defaults
    // selectedAdapter from the first adapter, so clicking earlier posts an empty
    // adapter — the test was passing on microtask timing rather than on the
    // component being ready.
    await screen.findByRole('option', { name: 'CottenDNS (A)' });

    await fireEvent.input(screen.getByPlaceholderText('Tunnel domain (e.g. dns.example.com)'), { target: { value: 'new.example.com' } });
    await fireEvent.click(screen.getByText('Create & Activate'));

    // POSITIVE: the create request used the backend's field name.
    expect(await screen.findByTestId('setup-panel')).toBeTruthy();
    expect(postBody).toEqual({ zone: 'new.example.com', adapter: 'cottendns', domains: [] });
    // POSITIVE: real delegation records rendered from the bundle (async load).
    expect(await screen.findByText('203.0.113.10')).toBeTruthy();

    await fireEvent.click(await screen.findByTestId('copy-config'));
    expect(copyCalled).toBe(true);

    await fireEvent.click(screen.getAllByText('Delete')[0]);
    expect(deleteCalled).toBe(true);
  });

  it('handles delete confirmation cancel', async () => {
    let deleteCalled = false;
    (globalThis as any).confirm = () => false;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'DELETE') deleteCalled = true;
      if (url.includes('/adapters')) return { ok: true, json: async () => ADAPTERS } as Response;
      if (url.includes('/zones')) return { ok: true, json: async () => [{ id: 1, zone: 't.example.com', adapter: 'cottendns', enabled: true }] } as Response;
      return { ok: true, json: async () => [] } as Response;
    };
    render(ForgeDNSView);
    await fireEvent.click(await screen.findByText('Delete'));
    expect(deleteCalled).toBe(false);
  });

  it('handles error paths in loadData / createZone', async () => {
    (globalThis as any).confirm = () => true;
    (globalThis as any).fetch = async () => { throw new Error('DNS Failure'); };
    render(ForgeDNSView);
    await fireEvent.input(screen.getByPlaceholderText('Tunnel domain (e.g. dns.example.com)'), { target: { value: 'err.example.com' } });
    await fireEvent.click(screen.getByText('Create & Activate'));
    expect(await screen.findByText('DNS Failure')).toBeTruthy();
  });
});
