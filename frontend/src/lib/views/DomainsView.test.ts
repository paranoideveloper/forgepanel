import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import DomainsView from './DomainsView.svelte';

function mockFetch(handler: (url: string, opts?: any) => any) {
  (globalThis as any).fetch = async (url: string, opts?: any) => {
    const res = handler(url, opts);
    return { ok: res.ok !== false, status: res.status || 200, json: async () => res.body ?? {} } as Response;
  };
}

describe('DomainsView', () => {
  it('shows the no-domain banner with REALITY guidance and can one-click a REALITY inbound', async () => {
    let realityCalled = false;
    mockFetch((url, opts) => {
      if (url.includes('/admin/domains-status')) {
        return {
          body: {
            has_domain: false,
            default_domain: '',
            count: 0,
            guidance_en: 'No domain is set.',
            guidance_fa: 'دامنه‌ای تنظیم نشده است.',
            domain_free: [
              { protocol: 'vless', security: 'reality', label: 'VLESS + REALITY', recommended: true, why: 'no domain needed' }
            ]
          }
        };
      }
      if (url.includes('/admin/inbounds/reality-quickstart') && opts?.method === 'POST') {
        realityCalled = true;
        return { status: 201, body: { id: 1, port: 28000 } };
      }
      if (url.endsWith('/admin/domains')) return { body: [] };
      return { body: {} };
    });

    render(DomainsView);
    await screen.findByText(/No domain configured/i);
    expect(screen.getByText(/VLESS \+ REALITY/i)).toBeTruthy();

    const btn = screen.getByText(/Create a REALITY inbound in one click/i);
    await fireEvent.click(btn);
    await waitFor(() => expect(realityCalled).toBe(true));
  });

  it('adds a domain', async () => {
    let created = '';
    mockFetch((url, opts) => {
      if (url.includes('/admin/domains-status')) {
        return { body: { has_domain: true, default_domain: 'a.example.com', count: 1, domain_free: [], guidance_en: '', guidance_fa: '' } };
      }
      if (url.endsWith('/admin/domains') && opts?.method === 'POST') {
        created = JSON.parse(opts.body).name;
        return { status: 201, body: { id: 2, name: created } };
      }
      if (url.endsWith('/admin/domains')) {
        return { body: [{ id: 1, name: 'a.example.com', is_default: true }] };
      }
      return { body: {} };
    });

    render(DomainsView);
    const input = await screen.findByPlaceholderText('vpn.example.com');
    await fireEvent.input(input, { target: { value: 'b.example.com' } });
    await fireEvent.click(screen.getByText('Add domain'));
    await waitFor(() => expect(created).toBe('b.example.com'));
  });
});
