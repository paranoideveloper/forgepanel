import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import InboundForm from './InboundForm.svelte';

// POST /protocols/switch/preview reports which fields a protocol change keeps,
// which it clears, which credentials it re-mints, whether the engine changes and
// whether the result would even start. It had no caller anywhere in the panel:
// changing the protocol dropdown ran applyDefaults() and the form emptied itself
// with no statement of what had just been thrown away — including, on an edit,
// the credential every existing client is using.

const schema = {
  protocols: [
    { proto: 'vless', label: 'VLESS', engine: 'xray', transports: ['tcp'], securities: ['none', 'reality'],
      fields: [{ key: 'uuid', label: 'UUID', type: 'text' }] },
    { proto: 'hysteria2', label: 'Hysteria2', engine: 'sing-box', transports: [], securities: ['tls'],
      fields: [{ key: 'password', label: 'Password', type: 'text' }] }
  ],
  common: [], transports: { tcp: [] }, securities: { none: [], reality: [], tls: [] }, fingerprints: []
};

const summary = {
  from_protocol: 'vless', to_protocol: 'hysteria2',
  from_engine: 'xray', to_engine: 'sing-box', engine_changed: true,
  retained: [{ field: 'port', value: '443' }],
  reset: [{ field: 'flow', why: 'hysteria2 has no flow' }],
  regenerated: [{ field: 'password', why: 'a credential belongs to the protocol that minted it' }],
  required_ports: [{ port: 443, why: 'UDP must be open' }],
  warnings: ['hysteria2 needs UDP reachability']
};

let posted: any[] = [];
function api(opts: { valid?: boolean; error?: string; fail?: boolean } = {}) {
  posted = [];
  (globalThis as any).localStorage = { getItem: () => 't', setItem: () => {}, removeItem: () => {} };
  (globalThis as any).fetch = async (url: string, o: any = {}) => {
    const path = String(url);
    if (path.includes('/protocols/schema')) return { ok: true, json: async () => schema } as Response;
    if (path.includes('/protocols/switch/preview')) {
      posted.push(JSON.parse(o.body));
      if (opts.fail) return { ok: false, status: 500, json: async () => ({ error: 'preview down' }) } as Response;
      return {
        ok: true,
        json: async () => ({
          summary,
          node: { protocol: 'hysteria2', port: 443, security: { type: 'tls' }, password: 'minted-fresh' },
          valid: opts.valid ?? true,
          error: opts.error
        })
      } as Response;
    }
    return { ok: true, json: async () => ({}) } as Response;
  };
}

async function switchToHysteria2() {
  render(InboundForm, { props: { initialProto: 'vless' } });
  const sel = (await screen.findByTestId('proto-select')) as HTMLSelectElement;
  await fireEvent.change(sel, { target: { value: 'hysteria2' } });
  return sel;
}

describe('InboundForm protocol switch', () => {
  beforeEach(() => api());
  afterEach(() => vi.restoreAllMocks());

  it('asks the server what the switch would do', async () => {
    await switchToHysteria2();
    await waitFor(() => expect(posted.length).toBeGreaterThan(0));
    // The node sent must describe where we are coming FROM. `bind:value` has
    // already moved the select to the target, so sending the bound protocol
    // would ask the server to describe a switch from hysteria2 to hysteria2.
    expect(posted[0].node.protocol).toBe('vless');
    expect(posted[0].target_protocol).toBe('hysteria2');
  });

  it('says which fields were cleared and which credentials were re-minted', async () => {
    await switchToHysteria2();
    const panel = await screen.findByTestId('switch-summary');
    expect(panel).toBeTruthy();
    expect((await screen.findByTestId('switch-reset')).textContent).toContain('flow');
    expect((await screen.findByTestId('switch-regenerated')).textContent).toContain('password');
    expect((await screen.findByTestId('switch-engine')).textContent).toContain('sing-box');
    expect((await screen.findByTestId('switch-port')).textContent).toContain('443');
    expect((await screen.findByTestId('switch-warning')).textContent).toContain('UDP');
  });

  it('reports a switch that would not start', async () => {
    api({ valid: false, error: 'hysteria2 requires tls' });
    await switchToHysteria2();
    expect((await screen.findByTestId('switch-invalid')).textContent).toContain('hysteria2 requires tls');
  });

  it('puts the previous protocol back when the switch is undone', async () => {
    const sel = await switchToHysteria2();
    await screen.findByTestId('switch-summary');
    expect(sel.value).toBe('hysteria2');
    await fireEvent.click(screen.getByTestId('switch-undo'));
    await waitFor(() => expect(sel.value).toBe('vless'));
    expect(screen.queryByTestId('switch-summary')).toBeNull();
  });

  // The preview explains a change; it does not authorise one. A panel that
  // refused to change protocol because the explanation was unavailable would be
  // a worse panel than the one that never explained anything.
  it('still switches when the preview cannot be reached', async () => {
    api({ fail: true });
    const sel = await switchToHysteria2();
    await waitFor(() => expect(sel.value).toBe('hysteria2'));
    expect(screen.queryByTestId('switch-summary')).toBeNull();
  });
});
