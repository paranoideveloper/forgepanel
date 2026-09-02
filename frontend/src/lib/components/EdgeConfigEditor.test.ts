import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import EdgeConfigEditor from './EdgeConfigEditor.svelte';

// The shape the panel route returns, mirroring a real Worker's config captured
// from a live deployment: config + the full key list + which keys were redacted.
const LIVE = {
  config: {
    subTitle: 'ForgeEdge',
    fingerprint: 'chrome',
    ports: [443, 8443],
    protocols: ['vless', 'trojan'],
    enableIPv6: false,
    cleanIPRandomCount: 10,
    warp: { remoteDNS: '1.1.1.1' },
    telegramBotToken: '__unchanged__',
    aBrandNewFieldFromANewerWorker: 'hello'
  },
  keys: [
    'subTitle', 'fingerprint', 'ports', 'protocols', 'enableIPv6',
    'cleanIPRandomCount', 'warp', 'telegramBotToken', 'aBrandNewFieldFromANewerWorker'
  ],
  redacted: ['telegramBotToken']
};

let puts: any[] = [];

function mockFetch(putResponse: any = { config: LIVE.config, changed: ['fingerprint'] }, fail = '') {
  (globalThis as any).fetch = async (url: string, opts: any = {}) => {
    if ((opts.method ?? 'GET') === 'PUT') {
      puts.push(JSON.parse(opts.body));
      if (fail) return { ok: false, status: 400, json: async () => ({ error: fail }) } as Response;
      return { ok: true, json: async () => putResponse } as Response;
    }
    return { ok: true, json: async () => LIVE } as Response;
  };
}

describe('EdgeConfigEditor', () => {
  beforeEach(() => {
    puts = [];
    (globalThis as any).localStorage = { getItem: () => 'tok', setItem: () => {}, removeItem: () => {} };
  });

  it('renders every field the Worker reports, not just the ones it knows', async () => {
    // The gap this closes: the panel could edit NOTHING while the bot drove all
    // ~60 fields. A field newer than this panel build must still be editable —
    // otherwise the editor silently caps what an operator can reach.
    mockFetch();
    render(EdgeConfigEditor, { props: { deploymentId: 1, onClose: () => {} } });

    expect(await screen.findByText('fingerprint')).toBeTruthy();
    expect(screen.getByText('subTitle')).toBeTruthy();
    expect(screen.getByText('aBrandNewFieldFromANewerWorker')).toBeTruthy();
  });

  it('sends only the fields that changed', async () => {
    // The whole safety property: a patch, not a replacement. Sending the full
    // document would delete any field this build does not lay out.
    mockFetch();
    render(EdgeConfigEditor, { props: { deploymentId: 1, onClose: () => {} } });
    const fp = (await screen.findByDisplayValue('chrome')) as HTMLInputElement;
    await fireEvent.input(fp, { target: { value: 'firefox' } });
    await fireEvent.click(screen.getByTestId('edge-config-save'));

    await waitFor(() => expect(puts.length).toBe(1));
    expect(puts[0]).toEqual({ fingerprint: 'firefox' });
    expect('aBrandNewFieldFromANewerWorker' in puts[0]).toBe(false);
    expect('subTitle' in puts[0]).toBe(false);
  });

  it('keeps a numeric list numeric', async () => {
    // Ports sent as strings are a value the Worker rejects, and the rejection
    // reads to an operator as "the panel ignored what I typed".
    mockFetch();
    render(EdgeConfigEditor, { props: { deploymentId: 1, onClose: () => {} } });
    const ports = (await screen.findByDisplayValue('443, 8443')) as HTMLInputElement;
    await fireEvent.input(ports, { target: { value: '443, 2053, 8443' } });
    await fireEvent.click(screen.getByTestId('edge-config-save'));

    await waitFor(() => expect(puts.length).toBe(1));
    expect(puts[0].ports).toEqual([443, 2053, 8443]);
  });

  it('does not send an untouched secret back', async () => {
    // The API replaces secrets with a sentinel on read. Sending it back would
    // ask the server to write the placeholder over a working credential; the
    // server drops it, and the editor should not send it in the first place.
    mockFetch();
    render(EdgeConfigEditor, { props: { deploymentId: 1, onClose: () => {} } });
    const sub = (await screen.findByDisplayValue('ForgeEdge')) as HTMLInputElement;
    await fireEvent.input(sub, { target: { value: 'MyEdge' } });
    await fireEvent.click(screen.getByTestId('edge-config-save'));

    await waitFor(() => expect(puts.length).toBe(1));
    expect('telegramBotToken' in puts[0]).toBe(false);
  });

  it('will not save while a JSON field is mid-edit', async () => {
    // A half-typed object would be rejected by the Worker with a message about
    // the field rather than about the typo.
    mockFetch();
    render(EdgeConfigEditor, { props: { deploymentId: 1, onClose: () => {} } });
    const warp = (await screen.findByDisplayValue(/remoteDNS/)) as HTMLTextAreaElement;
    await fireEvent.input(warp, { target: { value: '{ "remoteDNS": ' } });
    await fireEvent.click(screen.getByTestId('edge-config-save'));

    await waitFor(() => expect(puts.length).toBe(0));
  });

  it('saves nothing when nothing was touched', async () => {
    mockFetch();
    render(EdgeConfigEditor, { props: { deploymentId: 1, onClose: () => {} } });
    await screen.findByText('fingerprint');
    await fireEvent.click(screen.getByTestId('edge-config-save'));
    expect(puts.length).toBe(0);
  });
});
