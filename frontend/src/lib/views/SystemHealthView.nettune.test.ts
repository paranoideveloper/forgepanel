import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import SystemHealthView from './SystemHealthView.svelte';

const toasts: Array<{ msg: string; kind: string }> = [];
vi.mock('$lib/components/Toast.svelte', async () => {
  const actual = await vi.importActual<any>('$lib/components/Toast.svelte');
  return { ...actual, showToast: (msg: string, kind = 'info') => { toasts.push({ msg, kind }); } };
});

// The panel could apply BBR from the API and from a restart, and an operator
// had no way to ask for it: the endpoint pair existed with no control anywhere
// in the UI, which is the same as not existing.

// api models the real handler, including the part that is easy to get wrong:
// the panel PERSISTS the operator's choice before it touches the host, and KEEPS
// it when the apply fails, so the setting is re-applied at the next boot. A mock
// that returned a constant enabled:false regardless of the POST it had just
// accepted made a test pass while asserting the opposite of what the product
// does — the switch snapping back — which would have blocked the correct
// behaviour as a regression.
function api(state: any, onPost?: (body: any) => any) {
  const posts: Array<{ url: string; body: any }> = [];
  let stored = { ...state };
  (globalThis as any).localStorage = { getItem: () => 't', setItem: () => {}, removeItem: () => {} };
  (globalThis as any).fetch = async (url: string, opts?: any) => {
    const path = String(url);
    if (opts?.method === 'POST' && path.includes('/settings/nettune')) {
      const body = JSON.parse(opts.body);
      posts.push({ url: path, body });
      // Persist first, exactly as handleSetNetTune does.
      stored = { ...stored, enabled: body.enabled };
      const res = onPost?.(body);
      if (res?.fail) return { ok: false, status: 500, json: async () => res.fail } as Response;
      return { ok: true, json: async () => ({ ...stored, ...body, enabled: body.enabled }) } as Response;
    }
    if (opts?.method === 'POST') return { ok: true, json: async () => ({}) } as Response;
    if (path.includes('/settings/nettune')) return { ok: true, json: async () => stored } as Response;
    return { ok: true, json: async () => ({}) } as Response;
  };
  return posts;
}

const onCubic = {
  enabled: false, congestion: 'cubic', qdisc: 'fq_codel',
  available: ['reno', 'cubic', 'bbr'], bbr_available: true,
  active: false, persisted: false, kernel: '6.8.0-31-generic'
};

describe('SystemHealthView network tuning card', () => {
  beforeEach(() => { toasts.length = 0; });
  afterEach(() => vi.restoreAllMocks());

  it('shows what the host is actually running, not just the toggle', async () => {
    api(onCubic);
    render(SystemHealthView);
    const status = await screen.findByTestId('nettune-status');
    await waitFor(() => expect(status.textContent).toContain('cubic'));
    expect(status.textContent).toContain('fq_codel');
    expect((await screen.findByTestId('nettune-toggle') as HTMLInputElement).checked).toBe(false);
  });

  it('asks the panel to enable BBR when the toggle is flipped', async () => {
    const posts = api(onCubic);
    render(SystemHealthView);
    const toggle = (await screen.findByTestId('nettune-toggle')) as HTMLInputElement;
    await fireEvent.click(toggle);
    await waitFor(() => expect(posts.length).toBe(1));
    expect(posts[0].url).toContain('/settings/nettune');
    expect(posts[0].body).toEqual({ enabled: true });
  });

  // The failure that matters: the host cannot do BBR. The panel must say so
  // where the operator flipped the switch, with the command that fixes it,
  // instead of leaving a switch that looks on.
  it('surfaces the failure and its remediation instead of a green toggle', async () => {
    api(onCubic, () => ({
      fail: { error: 'this kernel offers no BBR', remediation: 'apt-get install linux-modules-extra-6.8.0-31-generic' }
    }));
    render(SystemHealthView);
    const toggle = (await screen.findByTestId('nettune-toggle')) as HTMLInputElement;
    await fireEvent.click(toggle);
    const err = await screen.findByTestId('nettune-error');
    expect(err.textContent).toContain('no BBR');
    expect((await screen.findByTestId('nettune-remedy')).textContent).toContain('linux-modules-extra');
    // The switch STAYS ON, and that is deliberate. The backend persists the
    // operator's choice before it touches the host and keeps it when the apply
    // fails, so the panel re-applies it at the next boot and the next
    // maintenance sweep — a kernel that gains BBR after an apt-get and a reboot
    // then comes up with it on. The refusal is carried by the error and the
    // remediation beside the switch, not by silently un-ticking it.
    //
    // The original assertion here was toBe(false), and it passed only because
    // this mock's GET returns a constant enabled:false and ignores the POST it
    // just accepted. Against a mock that models the real persist-then-fail
    // handler the box is checked — so the test asserted behaviour the product
    // does not have, which is worse than no test: it would have blocked the
    // correct behaviour as a regression.
    expect((screen.getByTestId('nettune-toggle') as HTMLInputElement).checked).toBe(true);
  });
});
