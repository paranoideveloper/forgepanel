import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import InboundForm from './InboundForm.svelte';

// /studio/preview runs the SAME model.Validate() the create endpoint runs, so
// ok:false means the save is going to come back 400. That verdict was rendered
// only in the preview column beside the config and Save stayed live: the
// operator pressed it and got a toast repeating a message they had scrolled
// past. The sharpest case is AmneziaWG's S1+56 != S2 rule, which nothing in the
// form hints at.
const schema = {
  protocols: [{ proto: 'vless', transports: ['ws'], securities: ['tls'], fields: [] }],
  transports: { ws: [] },
  securities: { tls: [] }
};

function api(preview: any, opts: { hang?: boolean } = {}) {
  (globalThis as any).localStorage = { getItem: () => 't', setItem: () => {}, removeItem: () => {} };
  (globalThis as any).fetch = async (url: string, o: any = {}) => {
    const u = String(url);
    if (u.includes('/schema')) return { ok: true, json: async () => schema } as Response;
    if (u.includes('/studio/preview')) {
      if (opts.hang) return new Promise(() => {}) as any; // never resolves
      return { ok: true, json: async () => preview } as Response;
    }
    return { ok: true, json: async () => ({}) } as Response;
  };
}

const invalid = {
  ok: false,
  errors: [{ severity: 'error', message: 'amneziawg: S1+56 must not equal S2' }]
};

describe('InboundForm refuses a save the server will reject', () => {
  beforeEach(() => vi.useFakeTimers({ shouldAdvanceTime: true }));

  it('disables Save and says why when the server says the config is invalid', async () => {
    api(invalid);
    render(InboundForm, { props: { onSaved: () => {}, onCancel: () => {} } as any });
    const btn = await screen.findByTestId('save-inbound');
    await waitFor(() => expect((btn as HTMLButtonElement).disabled).toBe(true));
    // The reason has to be next to the button, not only in the preview column.
    const blocked = screen.getByTestId('save-blocked');
    expect(blocked.textContent).toContain('S1+56 must not equal S2');
  });

  it('allows Save when the server says the config is valid', async () => {
    api({ ok: true, uri: 'vless://x', errors: [] });
    render(InboundForm, { props: { onSaved: () => {}, onCancel: () => {} } as any });
    const btn = await screen.findByTestId('save-inbound');
    await waitFor(() => expect((btn as HTMLButtonElement).disabled).toBe(false));
    expect(screen.queryByTestId('save-blocked')).toBeNull();
  });

  it('a warning does not block: advisory findings are not a refusal', async () => {
    api({ ok: true, uri: 'vless://x', errors: [{ severity: 'warn', message: 'TLS with no SNI' }] });
    render(InboundForm, { props: { onSaved: () => {}, onCancel: () => {} } as any });
    const btn = await screen.findByTestId('save-inbound');
    await waitFor(() => expect((btn as HTMLButtonElement).disabled).toBe(false));
  });

  it('an unreachable preview does not block: it says nothing about the config', async () => {
    (globalThis as any).localStorage = { getItem: () => 't', setItem: () => {}, removeItem: () => {} };
    (globalThis as any).fetch = async (url: string) => {
      const u = String(url);
      if (u.includes('/schema')) return { ok: true, json: async () => schema } as Response;
      if (u.includes('/studio/preview')) throw new Error('network down');
      return { ok: true, json: async () => ({}) } as Response;
    };
    render(InboundForm, { props: { onSaved: () => {}, onCancel: () => {} } as any });
    const btn = await screen.findByTestId('save-inbound');
    // Give the failing preview time to land.
    await new Promise((r) => setTimeout(r, 400));
    expect((btn as HTMLButtonElement).disabled).toBe(false);
  });

  it('a preview still in flight does not block a save the backend would accept', async () => {
    api(invalid, { hang: true });
    render(InboundForm, { props: { onSaved: () => {}, onCancel: () => {} } as any });
    const btn = await screen.findByTestId('save-inbound');
    await new Promise((r) => setTimeout(r, 400));
    // No verdict has arrived, so nothing may be refused on its behalf.
    expect((btn as HTMLButtonElement).disabled).toBe(false);
    expect(screen.queryByTestId('save-blocked')).toBeNull();
  });
});
