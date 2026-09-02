import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import OnlineView from './OnlineView.svelte';
import {
  DEFAULT_PRESENCE_TTL_SECONDS,
  isPresent,
  presenceTtlSeconds,
  setPresenceTtlSeconds
} from '$lib/presence';

const now = new Date().toISOString();

const payload = {
  ttl_seconds: 120,
  users: [
    {
      user_id: 1,
      username: 'alice',
      last_seen: now,
      addresses: 5,
      sessions: [
        { ip: '203.0.113.7', inbound: 'vless-in', node: 'local', first_seen: now, last_seen: now, connections: 12 },
        { ip: '198.51.100.2', inbound: 'vless-in', node: 'local', first_seen: now, last_seen: now, connections: 3 }
      ]
    },
    {
      user_id: 2,
      username: 'bob',
      last_seen: now,
      addresses: 1,
      sessions: [
        { ip: '192.0.2.9', inbound: 'hy2-in', node: 'edge-1', first_seen: now, last_seen: now, connections: 1 }
      ]
    }
  ]
};

describe('OnlineView', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });
  afterEach(() => setPresenceTtlSeconds(DEFAULT_PRESENCE_TTL_SECONDS));

  it('lists connected users with their address counts', async () => {
    (globalThis as any).fetch = async () => ({ ok: true, json: async () => payload }) as Response;
    render(OnlineView);

    expect(await screen.findByText('alice')).toBeTruthy();
    expect(screen.getByText('bob')).toBeTruthy();
    // The count is what an operator scans for; one account on many addresses is
    // the shared-account signal.
    expect(screen.getByText('5')).toBeTruthy();
    expect(screen.getByTestId('summary').textContent).toContain('2 users');
  });

  it('shows source addresses only when asked for them', async () => {
    (globalThis as any).fetch = async () => ({ ok: true, json: async () => payload }) as Response;
    render(OnlineView);
    await screen.findByText('alice');

    // Collapsed by default: an address locates a person, and rendering every
    // one of them on an auto-refreshing screen puts that on display for anyone
    // who walks past.
    expect(screen.queryByText('203.0.113.7')).toBeNull();

    await fireEvent.click(screen.getAllByTestId('toggle')[0]);
    expect(await screen.findByText('203.0.113.7')).toBeTruthy();
    expect(screen.getByText('198.51.100.2')).toBeTruthy();
  });

  it('explains an empty list rather than just showing nothing', async () => {
    (globalThis as any).fetch = async () =>
      ({ ok: true, json: async () => ({ users: [], ttl_seconds: 120 }) }) as Response;
    render(OnlineView);

    // "Nobody is connected" is ambiguous on its own — an idle user drops off
    // this list without having disconnected, and an operator who does not know
    // the window reads the empty screen as an outage.
    const empty = await screen.findByTestId('empty');
    expect(empty.textContent).toContain('120');
  });

  it('keeps the last good picture when a poll fails', async () => {
    let calls = 0;
    (globalThis as any).fetch = async () => {
      calls++;
      if (calls === 1) return { ok: true, json: async () => payload } as Response;
      return { ok: false, status: 500, json: async () => ({ error: 'boom' }) } as Response;
    };

    vi.useFakeTimers({ shouldAdvanceTime: true });
    render(OnlineView);
    await vi.waitFor(() => expect(screen.getByText('alice')).toBeTruthy());

    await vi.advanceTimersByTimeAsync(11_000);
    await vi.waitFor(() => expect(screen.getByText('boom')).toBeTruthy());

    // Blanking the table on a failed poll reads as "everyone disconnected",
    // which is a far more alarming lie than a stale list with an error on it.
    expect(screen.getByText('alice')).toBeTruthy();
  });

  it('stops polling when the view goes away', async () => {
    let calls = 0;
    (globalThis as any).fetch = async () => {
      calls++;
      return { ok: true, json: async () => payload } as Response;
    };

    vi.useFakeTimers({ shouldAdvanceTime: true });
    const { unmount } = render(OnlineView);
    await vi.waitFor(() => expect(calls).toBe(1));

    unmount();
    const after = calls;
    await vi.advanceTimersByTimeAsync(60_000);
    // An interval that outlives its component keeps requesting for the life of
    // the page.
    expect(calls).toBe(after);
  });

  it('publishes the server window so every screen agrees on it', async () => {
    // ttl_seconds exists so readers do not have to guess the window. This view
    // is the only one that fetches it, so it has to hand it to the shared
    // presence module — otherwise the Users table's presence dot keeps its own
    // idea of "online" and the two screens disagree about the same person, as
    // they did when that dot carried a hardcoded three minutes.
    (globalThis as any).fetch = async () =>
      ({ ok: true, json: async () => ({ users: [], ttl_seconds: 300 }) }) as Response;
    render(OnlineView);

    await vi.waitFor(() => expect(presenceTtlSeconds()).toBe(300));

    const now = Date.now();
    expect(isPresent(new Date(now - 150_000).toISOString(), now)).toBe(true);
    expect(isPresent(new Date(now - 400_000).toISOString(), now)).toBe(false);
  });
});
