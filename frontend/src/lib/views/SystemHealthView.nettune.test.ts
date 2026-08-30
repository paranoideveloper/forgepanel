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

function api(state: any, onPost?: (body: any) => any) {
  const posts: Array<{ url: string; body: any }> = [];
  (globalThis as any).localStorage = { getItem: () => 't', setItem: () => {}, removeItem: () => {} };
  (globalThis as any).fetch = async (url: string, opts?: any) => {
    const path = String(url);
    if (opts?.method === 'POST' && path.includes('/settings/nettune')) {
      const body = JSON.parse(opts.body);
      posts.push({ url: path, body });
      const res = onPost?.(body);
      if (res?.fail) return { ok: false, status: 500, json: async () => res.fail } as Response;
      return { ok: true, json: async () => ({ ...state, ...body, enabled: body.enabled }) } as Response;
    }
    if (opts?.method === 'POST') return { ok: true, json: async () => ({}) } as Response;
    if (path.includes('/settings/nettune')) return { ok: true, json: async () => state } as Response;
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
    expect((screen.getByTestId('nettune-toggle') as HTMLInputElement).checked).toBe(false);
  });
});
