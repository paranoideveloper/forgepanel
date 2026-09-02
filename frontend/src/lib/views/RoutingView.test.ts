import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import RoutingView from './RoutingView.svelte';

// The toast host is not mounted in these tests, so what the operator is TOLD is
// observed here rather than in the DOM.
const toasts: Array<{ msg: string; kind: string }> = [];
vi.mock('$lib/components/Toast.svelte', async () => {
  const actual = await vi.importActual<any>('$lib/components/Toast.svelte');
  return {
    ...actual,
    showToast: (msg: string, kind = 'info') => {
      toasts.push({ msg, kind });
    }
  };
});

const outbound = {
  id: 1, tag: 'relay-de', protocol: 'socks',
  settings: { servers: [{ address: '10.0.0.1', port: 1080 }] },
  stream_settings: null, send_through: '', sort_order: 0, enabled: true, note: 'German exit'
};
const ruleA = {
  id: 10, name: 'ads', sort_order: 0, enabled: true,
  domain: ['geosite:category-ads-all'], ip: null, port: '', network: 'tcp,udp',
  protocol: null, inbound_tags: null, user_ids: null, outbound_tag: 'block'
};
const ruleB = {
  id: 11, name: 'ir-direct', sort_order: 1, enabled: true,
  domain: null, ip: ['geoip:ir'], port: '', network: 'tcp,udp',
  protocol: null, inbound_tags: null, user_ids: null, outbound_tag: 'direct'
};

function stub(handlers: { onPost?: (url: string, body: any) => any } = {}) {
  (globalThis as any).fetch = async (url: string, opts?: any) => {
    const u = String(url);
    if (opts?.method && opts.method !== 'GET') {
      handlers.onPost?.(u, opts.body ? JSON.parse(opts.body) : {});
      return { ok: true, json: async () => ({}) } as Response;
    }
    if (u.includes('/routing/outbounds')) {
      return { ok: true, json: async () => ({ outbounds: [outbound], builtin: ['direct', 'block'] }) } as Response;
    }
    if (u.includes('/routing/rules')) {
      return {
        ok: true,
        json: async () => ({
          rules: [ruleA, ruleB],
          precedence: ['the panel’s own API', 'per-inbound relay chains (egress)', 'these rules, in order', 'anything unmatched goes direct']
        })
      } as Response;
    }
    return { ok: true, json: async () => ({}) } as Response;
  };
}

describe('RoutingView', () => {
  beforeEach(() => {
    (globalThis as any).confirm = () => true;
    toasts.length = 0;
  });

  it('shows the evaluation order rather than leaving it to be discovered', async () => {
    stub();
    render(RoutingView);
    const box = await screen.findByTestId('precedence');
    // Getting this wrong can pull traffic out of a relay chain and expose the
    // server's real address, so it is on the screen, not in a doc somewhere.
    expect(box.textContent).toContain('relay chains');
    expect(box.textContent).toContain('First match wins');
  });

  it('lists rules in evaluation order with what they match', async () => {
    stub();
    render(RoutingView);
    expect(await screen.findByText('ads')).toBeTruthy();
    expect(screen.getByText('ir-direct')).toBeTruthy();
    // The summary is what makes a rule list readable at a glance; without it
    // every rule looks the same and the order cannot be reasoned about.
    expect(screen.getByText(/geosite:category-ads-all/)).toBeTruthy();
  });

  it('refuses to save a rule with no conditions', async () => {
    stub();
    render(RoutingView);
    await screen.findByText('ads');
    await fireEvent.click(screen.getByTestId('new-rule'));

    const save = (await screen.findByTestId('save-rule')) as HTMLButtonElement;
    // A condition-less rule matches everything and swallows every rule below
    // it, so the operator finds out at the form rather than from a rejection.
    expect(save.disabled).toBe(true);
    expect(screen.getByTestId('rule-warning')).toBeTruthy();

    await fireEvent.input(screen.getByTestId('rule-domain'), { target: { value: 'example.com' } });
    expect((screen.getByTestId('save-rule') as HTMLButtonElement).disabled).toBe(false);
  });

  it('sends the COMPLETE rule order when reordering', async () => {
    let posted: any = null;
    stub({ onPost: (url, body) => { if (url.includes('reorder')) posted = body; } });
    render(RoutingView);
    await screen.findByText('ads');

    await fireEvent.click(screen.getAllByTitle('Later')[0]);
    await vi.waitFor(() => expect(posted).not.toBeNull());
    // A partial list leaves the omitted rules wherever they were — an order
    // nobody designed, live, on a first-match table. The API refuses it, and
    // the UI must not be the thing that sends one.
    expect(posted.ids).toEqual([11, 10]);
  });

  it('rejects malformed outbound JSON before sending it', async () => {
    let posted = false;
    stub({ onPost: (url) => { if (url.includes('outbounds')) posted = true; } });
    render(RoutingView);
    await screen.findByText('relay-de');
    await fireEvent.click(screen.getByTestId('new-outbound'));

    await fireEvent.input(screen.getByTestId('ob-tag'), { target: { value: 'x' } });
    await fireEvent.input(screen.getByTestId('ob-settings'), { target: { value: '{not json' } });
    await fireEvent.click(screen.getByTestId('save-outbound'));

    // Sending it would surface as an engine error on the next reload, by which
    // time the operator is nowhere near the field they typed it into.
    await vi.waitFor(() => expect(toasts.length).toBeGreaterThan(0));
    expect(toasts[0].msg).toMatch(/not valid JSON/);
    expect(toasts[0].kind).toBe('error');
    expect(posted).toBe(false);
  });

  it('offers built-in and configured outbounds as rule targets', async () => {
    stub();
    render(RoutingView);
    await screen.findByText('ads');
    await fireEvent.click(screen.getByTestId('new-rule'));

    const select = (await screen.findByTestId('rule-outbound')) as HTMLSelectElement;
    const values = Array.from(select.options).map((o) => o.value);
    expect(values).toContain('direct');
    expect(values).toContain('block');
    // A configured outbound the operator cannot select is a configured outbound
    // that does nothing.
    expect(values).toContain('relay-de');
  });

  it('explains an empty rule list instead of showing a blank panel', async () => {
    (globalThis as any).fetch = async (url: string) => {
      const u = String(url);
      if (u.includes('/routing/outbounds')) {
        return { ok: true, json: async () => ({ outbounds: [], builtin: ['direct', 'block'] }) } as Response;
      }
      return { ok: true, json: async () => ({ rules: [], precedence: [] }) } as Response;
    };
    render(RoutingView);
    const empty = await screen.findByTestId('no-rules');
    // "No rules" needs to say what that MEANS, or an operator cannot tell
    // whether routing is off or broken.
    expect(empty.textContent).toContain('relay chains apply');
  });
});
