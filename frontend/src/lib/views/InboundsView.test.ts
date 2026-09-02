import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import InboundsView from './InboundsView.svelte';

// The toast host is not mounted here, so what the operator is TOLD is observed
// through the mock rather than in the DOM.
const toasts: Array<{ msg: string; kind: string }> = [];
vi.mock('$lib/components/Toast.svelte', async () => {
  const actual = await vi.importActual<any>('$lib/components/Toast.svelte');
  return { ...actual, showToast: (msg: string, kind = 'info') => { toasts.push({ msg, kind }); } };
});

// Three inbound lifecycle capabilities existed on the server with nothing in the
// panel that could reach them:
//
//  - undo: POST /admin/inbounds/:id/undo restores PrevNodeJSON, which every edit
//    writes. No button, so the one-level history was written on every save and
//    read by nobody.
//  - bulk set-domain: the bulk endpoint's fourth action, cascading to SNI/Host,
//    while the bulk bar offered only enable/disable/delete.
//  - the "not serving" badge: the table renders it, the detector computes and
//    stores the reason, and the list endpoint left the field out of the payload,
//    so an inbound carrying no traffic still displayed as Enabled and nothing
//    anywhere said why.

const base = {
  id: 3, remark: 'edge', protocol: 'vless', port: 8443, enabled: true,
  node: { transport: { network: 'tcp' }, security: { type: 'reality' } }
};

function stub(rows: any[], onPost?: (url: string, body: any) => any) {
  const posts: { url: string; body: any }[] = [];
  (globalThis as any).fetch = async (url: string, opts?: any) => {
    const path = String(url);
    if (opts?.method === 'POST') {
      const body = opts.body ? JSON.parse(opts.body) : {};
      posts.push({ url: path, body });
      return { ok: true, json: async () => onPost?.(path, body) ?? {} } as Response;
    }
    if (path === '/api/admin/inbounds') return { ok: true, json: async () => rows } as Response;
    return { ok: true, json: async () => ({}) } as Response;
  };
  return posts;
}

describe('InboundsView lifecycle actions', () => {
  beforeEach(() => {
    (globalThis as any).confirm = () => true;
    toasts.length = 0;
  });
  afterEach(() => vi.restoreAllMocks());

  it('offers undo only for an inbound that has something to restore', async () => {
    stub([{ ...base, can_undo: true }, { ...base, id: 4, remark: 'fresh', can_undo: false }]);
    render(InboundsView);
    await screen.findByText('edge');
    // One button, not two: an inbound that was never edited has no previous
    // config, and a button that can only answer 409 is worse than no button.
    expect(screen.getAllByTestId('undo-btn')).toHaveLength(1);
  });

  it('posts to the undo endpoint for the right inbound', async () => {
    const posts = stub([{ ...base, can_undo: true }]);
    render(InboundsView);
    await screen.findByText('edge');
    await fireEvent.click(screen.getByTestId('undo-btn'));
    expect(posts[0].url).toBe('/api/admin/inbounds/3/undo');
  });

  it('sends the domain with a bulk set-domain, not an empty action', async () => {
    const posts = stub([{ ...base, can_undo: false }]);
    render(InboundsView);
    await screen.findByText('edge');
    await fireEvent.click(screen.getAllByRole('checkbox')[1]);
    await fireEvent.click(await screen.findByTestId('bulk-set-domain'));
    const input = await screen.findByTestId('bulk-domain-input');
    await fireEvent.input(input, { target: { value: 'cdn.example.org' } });
    await fireEvent.click(screen.getByTestId('bulk-domain-apply'));
    const bulk = posts.find((p) => p.url.endsWith('/inbounds/bulk'));
    expect(bulk?.body).toMatchObject({ action: 'set-domain', ids: [3], domain: 'cdn.example.org' });
  });

  it('reports a partial bulk result instead of calling it a success', async () => {
    // The endpoint returns per-id results and can succeed for some ids only.
    // Announcing "done" for the whole batch is how an operator learns weeks
    // later that two inbounds never took the change.
    stub([{ ...base, can_undo: false }], (url) =>
      url.endsWith('/inbounds/bulk')
        ? { action: 'set-domain', succeeded: 0, total: 1, results: [{ id: 3, ok: false, error: 'invalid domain' }] }
        : {}
    );
    render(InboundsView);
    await screen.findByText('edge');
    await fireEvent.click(screen.getAllByRole('checkbox')[1]);
    await fireEvent.click(await screen.findByTestId('bulk-set-domain'));
    await fireEvent.click(screen.getByTestId('bulk-domain-apply'));
    await waitFor(() => expect(toasts.length).toBeGreaterThan(0));
    const told = toasts.at(-1);
    expect(told?.kind).toBe('error');
    expect(told?.msg).toContain('invalid domain');
    expect(told?.msg).toContain('0');
  });

  it('shows the not-serving badge when the list says an enabled inbound is not running', async () => {
    stub([{ ...base, not_serving_reason: 'no core can serve ssh as an inbound' }]);
    render(InboundsView);
    await screen.findByText('edge');
    expect(await screen.findByTestId('not-serving')).toBeTruthy();
  });

  it('shows no not-serving badge for a healthy inbound', async () => {
    stub([base]);
    render(InboundsView);
    await screen.findByText('edge');
    expect(screen.queryByTestId('not-serving')).toBeNull();
  });
});
