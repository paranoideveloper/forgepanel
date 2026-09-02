import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import InboundForm from './InboundForm.svelte';

// GET /api/capabilities has always reported which protocol/transport/security
// combinations the pinned engines accept. The builder read exactly one field of
// it — port_hopping — so the security dropdown offered REALITY over WebSocket,
// the operator filled in the whole form, pressed Save, and the validator
// returned a 400 it could have given before the first field was typed.

const schema = {
  protocols: [{
    proto: 'vless', label: 'VLESS', engine: 'xray',
    transports: ['tcp', 'ws'], securities: ['none', 'tls', 'reality'],
    fields: [{ key: 'uuid', label: 'UUID', type: 'text' }]
  }],
  common: [], transports: { tcp: [], ws: [] },
  securities: { none: [], tls: [], reality: [] }, fingerprints: []
};

const combinations = [
  { protocol: 'vless', transport: 'tcp', security: 'none', supported: true },
  { protocol: 'vless', transport: 'tcp', security: 'tls', supported: true },
  { protocol: 'vless', transport: 'tcp', security: 'reality', supported: true },
  { protocol: 'vless', transport: 'ws', security: 'none', supported: true },
  { protocol: 'vless', transport: 'ws', security: 'tls', supported: true },
  {
    protocol: 'vless', transport: 'ws', security: 'reality', supported: false,
    reason: 'REALITY only supports tcp, xhttp or grpc transport, not "ws"'
  }
];

function api(caps: any = { combinations }) {
  (globalThis as any).localStorage = { getItem: () => 't', setItem: () => {}, removeItem: () => {} };
  (globalThis as any).fetch = async (url: string) => {
    const p = String(url);
    if (p.includes('/protocols/schema')) return { ok: true, json: async () => schema } as Response;
    if (p.includes('/capabilities')) {
      if (caps === null) return { ok: false, status: 500, json: async () => ({ error: 'down' }) } as Response;
      return { ok: true, json: async () => caps } as Response;
    }
    return { ok: true, json: async () => ({}) } as Response;
  };
}

const optionFor = (sel: HTMLSelectElement, value: string) =>
  [...sel.options].find((o) => o.value === value)!;

async function mounted() {
  render(InboundForm, { props: { initialProto: 'vless' } });
  const sec = (await screen.findByTestId('security-select')) as HTMLSelectElement;
  // wait for /capabilities, which is fetched after the schema
  await waitFor(() => expect(optionFor(sec, 'reality').disabled).toBe(false));
  return {
    sec,
    transport: screen.getByTestId('transport-select') as HTMLSelectElement
  };
}

describe('InboundForm capability matrix', () => {
  beforeEach(() => api());
  afterEach(() => vi.restoreAllMocks());

  it('greys out a security the engine cannot serve on the chosen transport', async () => {
    const { sec, transport } = await mounted();
    await fireEvent.change(transport, { target: { value: 'ws' } });
    await waitFor(() => expect(optionFor(sec, 'reality').disabled).toBe(true));
    // Not everything — tls over ws is fine, and disabling it would be the same
    // defect in the other direction.
    expect(optionFor(sec, 'tls').disabled).toBe(false);
  });

  it("shows the validator's own reason on the disabled option", async () => {
    const { sec, transport } = await mounted();
    await fireEvent.change(transport, { target: { value: 'ws' } });
    await waitFor(() =>
      expect(optionFor(sec, 'reality').title).toContain('REALITY only supports tcp, xhttp or grpc')
    );
  });

  it('moves the selection off a security that the new transport invalidates, and says so', async () => {
    const { sec, transport } = await mounted();
    // The form defaults to reality on tcp.
    expect(sec.value).toBe('reality');
    await fireEvent.change(transport, { target: { value: 'ws' } });
    await waitFor(() => expect(sec.value).not.toBe('reality'));
    // Silently changing a setting the operator chose is the other way to get
    // this wrong: they must be told.
    expect((await screen.findByTestId('security-moved')).textContent).toContain('REALITY only supports');
  });

  // Unknown must mean allowed. An older panel, or a capabilities call that
  // failed, must not silently forbid combinations that work.
  it('leaves every option selectable when the capability report cannot be reached', async () => {
    api(null);
    render(InboundForm, { props: { initialProto: 'vless' } });
    const sec = (await screen.findByTestId('security-select')) as HTMLSelectElement;
    const transport = screen.getByTestId('transport-select') as HTMLSelectElement;
    await fireEvent.change(transport, { target: { value: 'ws' } });
    await waitFor(() => expect(transport.value).toBe('ws'));
    expect(optionFor(sec, 'reality').disabled).toBe(false);
  });
});
