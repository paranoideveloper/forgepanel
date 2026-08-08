/**
 * Machine access to the panel API + the WARP .conf download.
 *
 * The claim under test: the ForgePanel VPS, which has no browser session and no
 * admin password, can drive the machine-safe panel actions with the feed push
 * token alone — and only with it — and can pull a WARP .conf (plain + Amnezia)
 * built from the registered account. This is what lets the panel offer one-click
 * "free WARP + Amnezia" without ever handling the Worker's admin password.
 */

import { describe, expect, test } from 'bun:test';
import { handlePanelAPI, type PanelContext } from '../src/panel/handler';
import { defaultConfig, KV_KEYS, type EdgeSecrets } from '../src/config/schema';
import { hashPassword } from '../src/config/store';
import type { WarpAccount } from '../src/warp/account';

const PATH = 'k7m2qxr9tzab34cd6efg8hjk';
const PUSH = 'unit-push-token-abcdef';

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

function secrets(): EdgeSecrets {
  const salt = 'testsalt';
  return {
    securePath: PATH,
    sessionKey: 'unit-test-session-key-0123456789',
    feedPushToken: PUSH,
    adminSalt: salt,
    adminHash: hashPassword(salt, 'correct-horse-battery'),
    createdAt: '2026-01-01T00:00:00Z',
    rotatedAt: '2026-01-01T00:00:00Z',
  };
}

const ACCOUNT: WarpAccount = {
  privateKey: 'aFakeClientPrivateKeyBase64==',
  publicKey: 'aFakePeerPublicKeyBase64==',
  warpIPv6: '2606:4700:110:8000:1:2:3:4/128',
  reserved: 'AAAA',
};

function ctx(kv: ReturnType<typeof makeKV>): PanelContext {
  return {
    env: { KV: kv } as never,
    cfg: defaultConfig(),
    secrets: secrets(),
    origin: `https://x.example`,
    host: 'x.example',
  };
}

function req(method: string, auth?: string): Request {
  const h: Record<string, string> = {};
  if (auth) h['Authorization'] = `Bearer ${auth}`;
  return new Request('https://x.example/', { method, headers: h });
}

describe('WARP .conf over the machine channel', () => {
  test('the feed push token authorises warp/conf; nothing else does', async () => {
    const kv = makeKV({ [KV_KEYS.warp]: [ACCOUNT] });

    // No credential → 401.
    const anon = await handlePanelAPI(req('GET'), ['warp', 'conf'], ctx(kv));
    expect(anon.status).toBe(401);

    // Wrong bearer → 401.
    const wrong = await handlePanelAPI(req('GET', 'not-the-token'), ['warp', 'conf'], ctx(kv));
    expect(wrong.status).toBe(401);

    // The push token → 200 with both variants.
    const ok = await handlePanelAPI(req('GET', PUSH), ['warp', 'conf'], ctx(kv));
    expect(ok.status).toBe(200);
    const body = (await ok.json()) as { success: boolean; body: { plain: string; pro: string } };
    expect(body.success).toBe(true);
    // plain is a standard wg-quick .conf; pro carries the AmneziaWG junk lines.
    expect(body.body.plain).toContain('[Interface]');
    expect(body.body.plain).toContain('PrivateKey = ' + ACCOUNT.privateKey);
    expect(body.body.plain).not.toContain('Jc =');
    expect(body.body.pro).toContain('Jc =');
    expect(body.body.pro).toContain('Jmin =');
    // WARP's server is not Amnezia-aware: init-packet junk must be 0.
    expect(body.body.pro).toContain('S1 = 0');
    expect(body.body.pro).toContain('S2 = 0');
  });

  test('warp/conf is a clear 404 before any WARP account is registered', async () => {
    const kv = makeKV(); // no accounts
    const res = await handlePanelAPI(req('GET', PUSH), ['warp', 'conf'], ctx(kv));
    expect(res.status).toBe(404);
  });

  test('warp/accounts imports pushed accounts and rejects an empty push', async () => {
    const kv = makeKV();
    const post = (body: unknown) =>
      new Request('https://x.example/', {
        method: 'POST',
        headers: { Authorization: `Bearer ${PUSH}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

    // No accounts → a clear 400, never a self-registration attempt (the Worker
    // cannot reach the WARP API).
    const empty = await handlePanelAPI(post({ accounts: [] }), ['warp', 'accounts'], ctx(kv));
    expect(empty.status).toBe(400);

    // Valid accounts → stored, and then served by warp/conf.
    const ok = await handlePanelAPI(post({ accounts: [ACCOUNT] }), ['warp', 'accounts'], ctx(kv));
    expect(ok.status).toBe(200);
    const stored = (await kv.get(KV_KEYS.warp, { type: 'json' })) as WarpAccount[];
    expect(stored).toHaveLength(1);
    expect(stored[0].publicKey).toBe(ACCOUNT.publicKey);

    const conf = await handlePanelAPI(req('GET', PUSH), ['warp', 'conf'], ctx(kv));
    expect(conf.status).toBe(200);
  });
});
