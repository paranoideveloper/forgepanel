import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import StudioView from './StudioView.svelte';

// The studio's shortcuts were ten hardcoded entries that set nothing but the
// protocol, while GET /protocols/presets served fourteen complete nodes —
// protocol, transport, security and flow together, each validated against the
// pinned engines. The button labelled "VLESS + REALITY" therefore selected vless
// and left the security to whatever the form's own defaults produced, and no
// shortcut could express a transport at all.

const presets = [
  {
    id: 'vless-reality-vision', name: 'VLESS · REALITY · Vision',
    description: 'server-side English', engine: 'xray', cdn: false,
    node: { protocol: 'vless', flow: 'xtls-rprx-vision', transport: { network: 'tcp' }, security: { type: 'reality' } }
  },
  {
    id: 'vless-ws-tls-cdn', name: 'VLESS · WebSocket · TLS (CDN)',
    description: 'server-side English', engine: 'xray', cdn: true,
    node: { protocol: 'vless', transport: { network: 'ws', path: '/' }, security: { type: 'tls' } }
  }
];

const schema = {
  protocols: [{
    proto: 'vless', label: 'VLESS', engine: 'xray',
    transports: ['tcp', 'ws'], securities: ['none', 'tls', 'reality'],
    chainable: true, serves_inbound: true,
    fields: [{ key: 'uuid', label: 'UUID', type: 'text' }]
  }],
  common: [], transports: { tcp: [], ws: [] }, securities: {}, fingerprints: ['chrome']
};

function stub(list: any[] = presets, fail = false) {
  (globalThis as any).fetch = async (url: string) => {
    const path = String(url);
    if (path.endsWith('/protocols/presets')) {
      if (fail) return { ok: false, status: 500, json: async () => ({ error: 'presets exploded' }) } as Response;
      return { ok: true, json: async () => ({ presets: list }) } as Response;
    }
    if (path.endsWith('/protocols/schema')) return { ok: true, json: async () => schema } as Response;
    return { ok: true, json: async () => ({}) } as Response;
  };
}

describe('StudioView presets', () => {
  beforeEach(() => stub());
  afterEach(() => vi.restoreAllMocks());

  it('renders the presets the server serves, not a hardcoded list', async () => {
    render(StudioView);
    await waitFor(() => expect(screen.getAllByTestId('studio-preset')).toHaveLength(2));
    const ids = screen.getAllByTestId('studio-preset').map((b) => b.getAttribute('data-preset'));
    expect(ids).toEqual(['vless-reality-vision', 'vless-ws-tls-cdn']);
  });

  it('marks the CDN-frontable preset and only that one', async () => {
    render(StudioView);
    await waitFor(() => expect(screen.getAllByTestId('studio-preset')).toHaveLength(2));
    expect(screen.getAllByTestId('preset-cdn')).toHaveLength(1);
  });

  it('seeds the form with the whole preset node, not just its protocol', async () => {
    render(StudioView);
    await waitFor(() => expect(screen.getAllByTestId('studio-preset')).toHaveLength(2));
    // The second preset is ws+tls. If only the protocol were passed, the form
    // would keep its own defaults (tcp/reality) and the operator would build
    // something other than what the button said.
    await fireEvent.click(screen.getAllByTestId('studio-preset')[1]);
    await waitFor(() => {
      const transport = screen.getByTestId('transport-select') as HTMLSelectElement;
      expect(transport.value).toBe('ws');
    });
    expect((screen.getByTestId('security-select') as HTMLSelectElement).value).toBe('tls');
  });

  it('says so when the presets cannot be loaded rather than showing an empty column', async () => {
    stub([], true);
    render(StudioView);
    expect(await screen.findByTestId('studio-presets-error')).toBeTruthy();
  });
});
