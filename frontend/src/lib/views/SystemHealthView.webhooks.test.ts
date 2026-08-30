import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import SystemHealthView from './SystemHealthView.svelte';

const toasts: Array<{ msg: string; kind: string }> = [];
vi.mock('$lib/components/Toast.svelte', async () => {
  const actual = await vi.importActual<any>('$lib/components/Toast.svelte');
  return { ...actual, showToast: (msg: string, kind = 'info') => { toasts.push({ msg, kind }); } };
});

// The panel grew a full webhook subsystem — signed deliveries, a retry queue,
// a closed set of event names — and the only way to point one at a receiver was
// to write the REST call by hand. An operator who cannot see the endpoints
// cannot see that one of them has been failing since Tuesday either, which is
// the state the last_status column exists to make visible.

// api models the real handlers, including the two things a mock is most likely
// to get wrong and thereby prove nothing:
//   * the event list comes from the SERVER on every read, so the UI cannot
//     invent a name. An endpoint subscribed to "node_down" instead of
//     "node-down" is enabled, green, and permanently silent.
//   * create returns the minted secret ONCE. No later read carries it. A UI
//     that drops it has cost the operator the only copy.
function api(opts: { events?: string[]; rows?: any[]; testFails?: boolean } = {}) {
  const events = opts.events ?? ['node-down', 'cert-expiry', 'user.created'];
  let rows = opts.rows ?? [];
  const calls: Array<{ method: string; path: string; body?: any }> = [];
  let nextID = 100;
  (globalThis as any).localStorage = { getItem: () => 't', setItem: () => {}, removeItem: () => {} };
  (globalThis as any).fetch = async (url: string, init?: any) => {
    const path = String(url);
    const method = init?.method ?? 'GET';
    const body = init?.body ? JSON.parse(init.body) : undefined;
    if (path.includes('/settings/webhooks')) {
      calls.push({ method, path, body });
      if (method === 'POST' && path.endsWith('/test')) {
        if (opts.testFails) {
          return {
            ok: false, status: 502,
            json: async () => ({ ok: false, status: 401, error: 'unauthorized', message: 'the receiver refused it' })
          } as Response;
        }
        return { ok: true, json: async () => ({ ok: true, status: 204 }) } as Response;
      }
      if (method === 'POST') {
        const row = {
          id: nextID++, url: body.url, events: body.events ?? '', enabled: true,
          proxy_url: body.proxy_url ?? '', has_secret: true,
          last_status: 0, last_error: ''
        };
        rows = [...rows, row];
        // Shown once and never again — exactly like the create handler.
        return { ok: true, json: async () => ({ ...row, secret: 'whsec-minted-once', secret_note: 'shown once' }) } as Response;
      }
      if (method === 'DELETE') {
        const id = Number(path.split('/').pop());
        rows = rows.filter((r) => r.id !== id);
        return { ok: true, json: async () => ({ deleted: id }) } as Response;
      }
      if (method === 'PUT') {
        const id = Number(path.split('/').pop());
        rows = rows.map((r) => (r.id === id ? { ...r, ...body } : r));
        return { ok: true, json: async () => rows.find((r) => r.id === id) } as Response;
      }
      return { ok: true, json: async () => ({ webhooks: rows, events }) } as Response;
    }
    if (method !== 'GET') return { ok: true, json: async () => ({}) } as Response;
    return { ok: true, json: async () => ({}) } as Response;
  };
  return calls;
}

describe('SystemHealthView webhook endpoints card', () => {
  beforeEach(() => { toasts.length = 0; });
  afterEach(() => vi.restoreAllMocks());

  it('lists the endpoints the panel is actually delivering to, and why one is failing', async () => {
    api({
      rows: [{
        id: 7, url: 'https://ops.example/hook', events: 'node-down', enabled: true,
        proxy_url: '', has_secret: true, last_status: 401,
        last_error: 'unauthorized', last_attempt: '2026-08-30T04:00:00Z'
      }]
    });
    render(SystemHealthView);

    const row = await screen.findByTestId('webhook-row-7');
    expect(row.textContent).toContain('https://ops.example/hook');
    expect(row.textContent).toContain('node-down');
    // The whole reason to render a list rather than a count: a 401 since
    // Tuesday looks identical to "nothing happened" from anywhere else.
    expect(row.textContent).toContain('401');
    expect(row.textContent).toContain('unauthorized');
  });

  it('offers exactly the event names the server named, and invents none', async () => {
    // A set the UI could not have guessed — if the checkboxes come from a
    // hardcoded list in the component, this fails.
    api({ events: ['pool-exhausted', 'expiry-reminder'] });
    render(SystemHealthView);

    const box = await screen.findByTestId('webhook-event-pool-exhausted');
    expect(box).toBeTruthy();
    expect(await screen.findByTestId('webhook-event-expiry-reminder')).toBeTruthy();
    expect(screen.queryByTestId('webhook-event-node-down')).toBeNull();
  });

  it('shows the minted secret once, and does not pretend to have it later', async () => {
    api();
    render(SystemHealthView);
    await screen.findByTestId('webhook-url');

    await fireEvent.input(screen.getByTestId('webhook-url'), {
      target: { value: 'https://ops.example/new' }
    });
    await fireEvent.click(screen.getByTestId('webhook-create'));

    // THE load-bearing assertion. The receiver needs this to verify
    // X-ForgePanel-Signature and the panel will never hand it back; a UI that
    // drops it has destroyed the only copy while reporting success.
    const reveal = await screen.findByTestId('webhook-secret-reveal');
    await waitFor(() => expect(reveal.textContent).toContain('whsec-minted-once'));

    // And it must not be conjured back from a plain list read, which carries
    // has_secret and nothing else.
    await fireEvent.click(screen.getByTestId('webhook-refresh'));
    await waitFor(() => expect(screen.queryByTestId('webhook-secret-reveal')).toBeNull());
  });

  it('reports the receivers own status code when a test delivery is refused', async () => {
    api({
      testFails: true,
      rows: [{ id: 9, url: 'https://ops.example/hook', events: '', enabled: true, proxy_url: '', has_secret: true }]
    });
    render(SystemHealthView);

    await fireEvent.click(await screen.findByTestId('webhook-test-9'));
    // "Delivery failed" is not actionable. 401 is.
    await waitFor(() => expect(screen.getByTestId('webhook-error').textContent).toContain('401'));
  });
});
