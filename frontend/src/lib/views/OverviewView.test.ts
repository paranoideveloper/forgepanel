import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import OverviewView from './OverviewView.svelte';

// The Overview is now a dashboard over /admin/dashboard. It previously showed
// liveness, a version, node counts and the panel's uptime, and an administrator
// checking whether the SERVER was healthy had to open a shell.

const dashboard = {
  status: 'ok',
  version: '1.20.0',
  panel: { uptime_seconds: 7200, public_address: 'panel.example.com' },
  system: {
    cpu: { cores: 4, load1: 0.33, load5: 0.25, load15: 0.25, percent: 8.25 },
    memory: { total: 8316702720, used: 1688862720, available: 6627840000, swap_total: 0, swap_used: 0 },
    disk: { path: '/', total: 160497381376, used: 21401260032, free: 139096121344 },
    network: { rx_bytes: 1083095928, tx_bytes: 184923319 },
    host: { hostname: 'vultr', os: 'Ubuntu 22.04.5 LTS', kernel: '5.15.0-187-generic', arch: 'amd64', uptime_seconds: 12371 }
  },
  traffic: { rx_bytes: 1083095928, tx_bytes: 184923319, rx_bytes_per_s: 99, tx_bytes_per_s: 66 },
  accounts: { users: 12, active: 9, disabled: 2, expired: 1, online: 3, admins: 1, owners: 1, resellers: 2, viewers: 0 },
  inbounds: { total: 12, enabled: 11, disabled: 1, not_serving: 1, by_protocol: { vless: 5, vmess: 1, wireguard: 1 } },
  nodes: { online: 3, total: 3 },
  warnings: ['VLESS · WS · TLS (CDN): address is not one this server can bind']
};

describe('OverviewView', () => {
  let fetchCount = 0;
  beforeEach(() => {
    fetchCount = 0;
    vi.useFakeTimers({ shouldAdvanceTime: true });
    (globalThis as any).fetch = async () => {
      fetchCount++;
      return { ok: true, json: async () => dashboard } as Response;
    };
  });
  afterEach(() => vi.useRealTimers());

  it('shows what the machine is doing, not just that the panel is alive', async () => {
    render(OverviewView);
    // The server's own vitals — the reason to build this at all.
    expect(await screen.findByText('8%')).toBeTruthy();                    // CPU
    expect(screen.getByText((t) => t.includes('Ubuntu 22.04.5 LTS'))).toBeTruthy();
    expect(screen.getByText((t) => t.includes('5.15.0-187-generic'))).toBeTruthy();
    expect(screen.getByText('vultr')).toBeTruthy();
    // Server uptime AND panel uptime are different facts and both are shown.
    expect(screen.getByText('3h 26m')).toBeTruthy();                       // 12371s
    expect(screen.getByText('2h 0m')).toBeTruthy();                        // 7200s
  });

  it('counts accounts and inbounds the operator has to act on', async () => {
    render(OverviewView);
    // Every section the operator reads to answer "who and what is this serving".
    for (const heading of ['Users', 'Administrators', 'Inbounds', 'Nodes']) {
      expect(await screen.findByText(heading)).toBeTruthy();
    }
    // "12" is both the user count and the inbound count, so assert on the
    // labelled figures rather than a bare number that appears twice.
    expect(screen.getAllByText('12').length).toBe(2);
    expect(screen.getByText('Resellers')).toBeTruthy();
    // An inbound the panel is NOT serving is the state that used to be
    // invisible: enabled in the UI, nothing listening, no explanation.
    expect(screen.getByText('Not serving')).toBeTruthy();
  });

  it('surfaces warnings rather than leaving them to be discovered', async () => {
    render(OverviewView);
    expect(await screen.findByText((t) => t.includes('address is not one this server can bind'))).toBeTruthy();
    expect(screen.getByText('Needs attention')).toBeTruthy();
  });

  it('shows the protocol mix', async () => {
    render(OverviewView);
    expect(await screen.findByText('Protocol distribution')).toBeTruthy();
    expect(screen.getByText('vless')).toBeTruthy();
    expect(screen.getByText('wireguard')).toBeTruthy();
  });

  it('refreshes on demand', async () => {
    render(OverviewView);
    const btn = await screen.findByText('Refresh');
    const before = fetchCount;
    await fireEvent.click(btn);
    expect(fetchCount).toBeGreaterThan(before);
  });

  // A panel mid-upgrade can still serve the older /overview shape. Throwing on a
  // missing field shows nothing at all rather than the half that is present.
  it('does not crash on a response missing the new fields', async () => {
    (globalThis as any).fetch = async () => ({
      ok: true,
      json: async () => ({ status: 'ok', version: '1.19.1' })
    } as Response);
    render(OverviewView);
    expect(await screen.findByText('Refresh')).toBeTruthy();
  });
});
