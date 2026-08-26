import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import InboundForm from './InboundForm.svelte';

const schema = {
  protocols: [{
    proto: 'vless', transports: ['ws'], securities: ['tls'],
    // An iselect whose options are STRINGS and whose default is a NUMBER —
    // exactly the shape shipped for shadowtls.version and reality xver.
    // default 2, deliberately NOT the first option: a broken numeric seed
    // matches nothing and Svelte falls back to the first option, so a default
    // that happens to be first would hide the bug entirely.
    fields: [{ key: 'shadowtls.version', label: 'Version', type: 'iselect', options: ['3', '2', '1'], default: 2 }]
  }],
  transports: { ws: [] },
  securities: { tls: [] }
};

type Call = { url: string; method: string };
let calls: Call[] = [];
let bodies: any[] = [];

function api(opts: { breakOnPut?: boolean } = {}) {
  let putCount = 0;
  (globalThis as any).localStorage = { getItem: () => 't', setItem: () => {}, removeItem: () => {} };
  (globalThis as any).fetch = async (url: string, o: any = {}) => {
    const method = o.method ?? 'GET';
    calls.push({ url: String(url), method });
    if (o.body) { try { bodies.push(JSON.parse(o.body)); } catch (_) {} }
    if (String(url).includes('/schema')) return { ok: true, json: async () => schema } as Response;
    if (method === 'PUT') {
      putCount++;
      if (opts.breakOnPut && putCount === 1) {
        return {
          ok: false, status: 409,
          json: async () => ({
            error: 'this edit invalidates handed-out configs',
            code: 'breaking_edit',
            breaking: ['port 443 → 8443', 'transport ws → grpc']
          })
        } as Response;
      }
      return { ok: true, json: async () => ({ id: 5 }) } as Response;
    }
    return { ok: true, json: async () => ({}) } as Response;
  };
}

describe('InboundForm breaking edits', () => {
  beforeEach(() => {
    calls = [];
    bodies = [];
  });

  it('does not send confirm=true before the operator has seen what breaks', async () => {
    // The safe-edit guard exists to tell an operator that a change invalidates
    // every config already handed out. Hardcoding confirm=true answered that
    // question for them every time: the guard ran, found breaking changes, and
    // was overruled before anyone saw it.
    api({ breakOnPut: true });
    render(InboundForm, { props: { onSaved: () => {}, initial: { protocol: 'vless' }, editId: 5 } });
    await waitFor(() => expect(calls.some((c) => c.url.includes('/schema'))).toBe(true));
    await fireEvent.click(await screen.findByTestId('save-inbound'));

    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    const first = calls.find((c) => c.method === 'PUT')!;
    expect(first.url).not.toContain('confirm=true');
  });

  it('shows which changes break, instead of a raw error', async () => {
    api({ breakOnPut: true });
    render(InboundForm, { props: { onSaved: () => {}, initial: { protocol: 'vless' }, editId: 5 } });
    await waitFor(() => expect(calls.some((c) => c.url.includes('/schema'))).toBe(true));
    await fireEvent.click(await screen.findByTestId('save-inbound'));

    const panel = await screen.findByTestId('breaking-edit');
    expect(panel.textContent).toContain('port 443');
    expect(panel.textContent).toContain('transport ws');
  });

  it('offers keep_old so clients are not cut off mid-migration', async () => {
    // keep_old leaves the current inbound alive but disabled as a migration
    // copy. It was reachable in the API and unreachable from the panel.
    api({ breakOnPut: true });
    render(InboundForm, { props: { onSaved: () => {}, initial: { protocol: 'vless' }, editId: 5 } });
    await waitFor(() => expect(calls.some((c) => c.url.includes('/schema'))).toBe(true));
    await fireEvent.click(await screen.findByTestId('save-inbound'));
    await fireEvent.click(await screen.findByTestId('breaking-keep-old'));

    await waitFor(() => {
      const puts = calls.filter((c) => c.method === 'PUT');
      expect(puts.some((c) => c.url.includes('keep_old=true') && c.url.includes('confirm=true'))).toBe(true);
    });
  });
});

describe('InboundForm iselect defaults', () => {
  beforeEach(() => {
    calls = [];
    bodies = [];
  });

  it('submits the documented iselect default, not the first option', async () => {
    // The schema default for an iselect is a NUMBER (shadowtls.version is 3,
    // reality xver is 0) while its options arrive as STRINGS. Svelte binds a
    // select by identity, so the numeric default matched no option and the
    // binding replaced it with the FIRST one. Nothing looked wrong — a value
    // was always selected — and the documented default silently was not the
    // default.
    //
    // Asserting the DOM's select.value fights the binding's internals; what
    // matters is the value that reaches the server.
    api();
    render(InboundForm, { props: { onSaved: () => {}, initialProto: 'vless' } });
    // Wait for onMount to FINISH, not just to have started. It awaits
    // /protocols/schema and then /capabilities before calling applyDefaults, so
    // waiting on the schema call alone races the seeding this test is about.
    // The transport select flipping to the protocol's own transport is the
    // observable signal that applyDefaults has run.
    await waitFor(() => {
      const t = document.querySelector('#transport') as HTMLSelectElement | null;
      expect(t?.value).toBe('ws');
    });
    await fireEvent.click(await screen.findByTestId('save-inbound'));

    await waitFor(() => expect(bodies.length).toBeGreaterThan(0));
    const sent = bodies[bodies.length - 1];
    expect(sent?.shadowtls?.version).toBe(2);
  });
});
