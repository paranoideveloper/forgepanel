/**
 * Edge connection limits.
 *
 * The load-bearing case is the router one: it proves the gate is consulted on
 * the real data path. A pure unit test of `admitIP` would pass against a
 * `limits.ts` that no request ever reaches, which is exactly the failure mode
 * this feature is at risk of.
 */

import { beforeEach, describe, expect, test } from 'bun:test';
import { route } from '../src/router';
import { admitIP, limiterSnapshot, releaseConnection, resetLimiter } from '../src/protocols/limits';
import { vlessOverWS } from '../src/protocols/vless';
import { trojanOverWS } from '../src/protocols/trojan';
import { DEFAULT_LIMITS, defaultConfig, KV_KEYS } from '../src/config/schema';
import { migrateConfig } from '../src/config/store';
import { validateConfig } from '../src/config/validate';
import type { LimitsConfig } from '../src/config/schema';

const LIM: LimitsConfig = {
  enabled: true,
  perIPConcurrent: 8,
  perIPNewPerMinute: 1,
  perUUIDConcurrent: 4,
};
const IP = '203.0.113.7';

function makeKV(seed: Record<string, unknown> = {}) {
  const store = new Map<string, string>();
  for (const [k, v] of Object.entries(seed)) store.set(k, JSON.stringify(v));
  return {
    async get(key: string, opts?: { type?: string }) {
      const raw = store.get(key);
      if (raw === undefined) return null;
      return opts?.type === 'json' ? JSON.parse(raw) : raw;
    },
    async put(key: string, value: string) { store.set(key, value); },
    async delete(key: string) { store.delete(key); },
  };
}

/**
 * Enough of a WebSocket for the handlers to install their listeners on. workerd
 * supplies WebSocketPair; bun does not, so without this the release hooks could
 * only ever be read, never run.
 */
class FakeSocket {
  readyState = 1;
  binaryType = '';
  private readonly listeners = new Map<string, ((ev: unknown) => void)[]>();

  accept(): void { /* workerd-only handshake */ }
  close(): void { this.readyState = 3; }
  send(): void { /* nothing reads it back in these cases */ }

  addEventListener(type: string, fn: (ev: unknown) => void): void {
    const bucket = this.listeners.get(type) ?? [];
    bucket.push(fn);
    this.listeners.set(type, bucket);
  }

  fire(type: string, ev: unknown = {}): void {
    for (const fn of [...(this.listeners.get(type) ?? [])]) fn(ev);
  }
}

let lastServer: FakeSocket | null = null;

(globalThis as unknown as { WebSocketPair: unknown }).WebSocketPair = function WebSocketPair() {
  const client = new FakeSocket();
  const server = new FakeSocket();
  lastServer = server;
  // Object.values() order is what the handlers destructure as [client, server].
  return { 0: client, 1: server };
};

// The registry is a module global (the runtime.ts:12-21 pattern), so cases in
// this file share it unless it is reset.
beforeEach(() => {
  resetLimiter();
  lastServer = null;
});

describe('edge connection limits', () => {
  test('a second connection from one IP inside the minute is refused at the router, not at the handler', async () => {
    const cfg = {
      ...defaultConfig(),
      limits: LIM,
      vlessUUID: '11111111-1111-4111-8111-111111111111',
      trojanPassword: 'x',
    };
    const env = { KV: makeKV({ [KV_KEYS.config]: cfg }) } as never;

    // Spend the one token the bucket holds, directly: routing a first
    // *successful* upgrade is impossible under bun (no WebSocketPair), which is
    // precisely why reaching the handler at all is the failure signal.
    expect(admitIP(IP, LIM).ok).toBe(true);

    const res = await route(new Request('https://w.example/vl/x', {
      headers: { Upgrade: 'websocket', 'CF-Connecting-IP': IP },
    }), env);

    expect(res.status).toBe(404);
  });

  test('the trojan path is gated too', async () => {
    const cfg = {
      ...defaultConfig(),
      limits: LIM,
      vlessUUID: '11111111-1111-4111-8111-111111111111',
      trojanPassword: 'x',
    };
    const env = { KV: makeKV({ [KV_KEYS.config]: cfg }) } as never;

    expect(admitIP(IP, LIM).ok).toBe(true);

    const res = await route(new Request('https://w.example/tr/x', {
      headers: { Upgrade: 'websocket', 'CF-Connecting-IP': IP },
    }), env);

    expect(res.status).toBe(404);
  });

  test('an unmatched upgrade path takes no slot', async () => {
    const cfg = {
      ...defaultConfig(),
      limits: { ...LIM, perIPNewPerMinute: 1000 },
      vlessUUID: '11111111-1111-4111-8111-111111111111',
      trojanPassword: 'x',
    };
    const env = { KV: makeKV({ [KV_KEYS.config]: cfg }) } as never;

    const res = await route(new Request('https://w.example/nope/x', {
      headers: { Upgrade: 'websocket', 'CF-Connecting-IP': IP },
    }), env);

    expect(res.status).toBe(404);
    // Nothing on that path can ever release a handle, so nothing may be taken.
    expect(limiterSnapshot().totalLive).toBe(0);
    expect(limiterSnapshot().ips).toBe(0);
  });

  test('the bucket refills after the window', () => {
    const t0 = 1_700_000_000_000;
    expect(admitIP(IP, LIM, t0).ok).toBe(true);

    const second = admitIP(IP, LIM, t0 + 1000);
    expect(second.ok).toBe(false);
    expect(second.ok === false && second.reason).toBe('ip-rate');

    expect(admitIP(IP, LIM, t0 + 61_000).ok).toBe(true);
  });

  test('perIPConcurrent frees a slot when releaseConnection runs', () => {
    const cfg: LimitsConfig = { ...LIM, perIPConcurrent: 2, perIPNewPerMinute: 1000 };
    const first = admitIP(IP, cfg);
    const second = admitIP(IP, cfg);
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);

    const third = admitIP(IP, cfg);
    expect(third.ok).toBe(false);
    expect(third.ok === false && third.reason).toBe('ip-concurrent');

    if (!first.ok) throw new Error('unreachable');
    releaseConnection(first.handle);
    expect(limiterSnapshot().totalLive).toBe(1);

    // Idempotent: close AND error both fire on a socket that errors out.
    releaseConnection(first.handle);
    expect(limiterSnapshot().totalLive).toBe(1);

    expect(admitIP(IP, cfg).ok).toBe(true);
  });

  test('an empty client IP is admitted without accounting', () => {
    expect(admitIP('', LIM).ok).toBe(true);
    expect(admitIP('', LIM).ok).toBe(true);
    expect(limiterSnapshot().ips).toBe(0);
    expect(limiterSnapshot().totalLive).toBe(0);
  });

  test('a disabled limiter admits everything', () => {
    const off: LimitsConfig = { ...LIM, enabled: false };
    for (let i = 0; i < 20; i++) expect(admitIP(IP, off).ok).toBe(true);
    expect(limiterSnapshot().ips).toBe(0);
  });

  test('migrateConfig fills a partial stored limits object', () => {
    // What the panel's free-form JSON textarea produces: a whole-key overwrite.
    const merged = migrateConfig({ limits: { enabled: false } } as never);
    expect(merged.limits.enabled).toBe(false);
    expect(merged.limits.perIPConcurrent).toBe(DEFAULT_LIMITS.perIPConcurrent);
    expect(merged.limits.perIPNewPerMinute).toBe(DEFAULT_LIMITS.perIPNewPerMinute);
    expect(merged.limits.perUUIDConcurrent).toBe(DEFAULT_LIMITS.perUUIDConcurrent);
  });

  test('validateConfig rejects a non-positive or non-integer limit', () => {
    const bad = { ...defaultConfig(), limits: { ...DEFAULT_LIMITS, perIPConcurrent: 0 } };
    expect(validateConfig(bad).length).toBeGreaterThan(0);

    const fractional = { ...defaultConfig(), limits: { ...DEFAULT_LIMITS, perIPNewPerMinute: 1.5 } };
    expect(validateConfig(fractional).length).toBeGreaterThan(0);

    const notBool = {
      ...defaultConfig(),
      limits: { ...DEFAULT_LIMITS, enabled: 'yes' as unknown as boolean },
    };
    expect(validateConfig(notBool).length).toBeGreaterThan(0);

    // The defaults themselves must not be what a fresh deploy trips over.
    expect(validateConfig({ ...defaultConfig(), trojanPassword: 'x' })).toEqual([]);
  });

  test('the vless handler gives the slot back when the socket closes', () => {
    const admit = admitIP(IP, LIM);
    if (!admit.ok) throw new Error('unreachable');
    expect(limiterSnapshot().totalLive).toBe(1);

    const res = vlessOverWS(new Request('https://w.example/vl/x'), {
      uuid: '11111111-1111-4111-8111-111111111111',
      outbound: { proxyIPMode: 'off', proxyIPs: [], nat64Prefixes: [], dohUpstream: '' },
      dohUpstream: '',
      handle: admit.handle,
    });
    expect(res.status).toBe(101);

    lastServer?.fire('close');
    expect(limiterSnapshot().totalLive).toBe(0);
  });

  test('the vless handler gives the slot back when the socket only errors', () => {
    const admit = admitIP(IP, LIM);
    if (!admit.ok) throw new Error('unreachable');

    vlessOverWS(new Request('https://w.example/vl/x'), {
      uuid: '11111111-1111-4111-8111-111111111111',
      outbound: { proxyIPMode: 'off', proxyIPs: [], nat64Prefixes: [], dohUpstream: '' },
      dohUpstream: '',
      handle: admit.handle,
    });

    // An errored socket need not also emit close — that is why both are hooked.
    lastServer?.fire('error');
    expect(limiterSnapshot().totalLive).toBe(0);

    // And a socket that emits both is still only counted once.
    lastServer?.fire('close');
    expect(limiterSnapshot().totalLive).toBe(0);
  });

  test('the trojan handler gives the slot back when the socket closes', () => {
    const admit = admitIP(IP, LIM);
    if (!admit.ok) throw new Error('unreachable');
    expect(limiterSnapshot().totalLive).toBe(1);

    const res = trojanOverWS(new Request('https://w.example/tr/x'), {
      password: 'x',
      outbound: { proxyIPMode: 'off', proxyIPs: [], nat64Prefixes: [], dohUpstream: '' },
      handle: admit.handle,
    });
    expect(res.status).toBe(101);

    lastServer?.fire('close');
    expect(limiterSnapshot().totalLive).toBe(0);
  });

  test('the IP registry stays bounded under a spoofed-source flood', () => {
    const cfg: LimitsConfig = { ...LIM, perIPConcurrent: 4, perIPNewPerMinute: 1000 };
    for (let i = 0; i < 12_000; i++) {
      const admit = admitIP(`198.51.100.${i}`, cfg);
      if (admit.ok) releaseConnection(admit.handle);
    }
    expect(limiterSnapshot().ips).toBeLessThanOrEqual(10_000);
  });
});
