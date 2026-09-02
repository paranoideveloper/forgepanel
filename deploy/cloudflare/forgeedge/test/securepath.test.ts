/**
 * The compulsory secure path and the session layer.
 *
 * These two are what stand between an internet-wide Worker scanner and an open
 * admin panel, so the tests are adversarial: wrong prefixes, near-miss paths,
 * case changes, percent-encoding, forged signatures, expired sessions, and the
 * "is the path actually random" property.
 */

import { describe, expect, test } from 'bun:test';
import {
  matchSecurePath, issueSession, verifySession, checkPassword,
  readCookie, sessionCookieHeader, clearSessionCookie, SESSION_COOKIE,
} from '../src/auth';
import { randomSecurePath, randomToken, hashPassword, migrateConfig } from '../src/config/store';
import { timingSafeEqual } from '../src/common/http';
import type { EdgeSecrets } from '../src/config/schema';

const PATH = 'k7m2qxr9tzab34cd6efg8hjk';

function secrets(overrides: Partial<EdgeSecrets> = {}): EdgeSecrets {
  const salt = 'testsalt';
  return {
    securePath: PATH,
    sessionKey: 'unit-test-session-key-0123456789',
    feedPushToken: 'push-token',
    adminSalt: salt,
    adminHash: hashPassword(salt, 'correct-horse-battery'),
    createdAt: '2026-01-01T00:00:00Z',
    rotatedAt: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

describe('secure-path gate', () => {
  test('matches and returns the remaining segments', () => {
    expect(matchSecurePath(`/${PATH}/panel`, PATH)).toEqual(['panel']);
    expect(matchSecurePath(`/${PATH}/sub/abc/clash`, PATH)).toEqual(['sub', 'abc', 'clash']);
    expect(matchSecurePath(`/${PATH}`, PATH)).toEqual([]);
    expect(matchSecurePath(`/${PATH}/`, PATH)).toEqual([]);
  });

  test('rejects everything that is not exactly the path', () => {
    for (const p of [
      '/', '/panel', '/sub/abc', '/admin',
      `/${PATH}x/panel`,
      `/x${PATH}/panel`,
      `/${PATH.slice(0, -1)}/panel`,
      `/${PATH.toUpperCase()}/panel`,
      `/wrong/${PATH}/panel`,
      '/.env', '/wp-login.php', '/favicon.ico',
    ]) {
      expect(matchSecurePath(p, PATH), p).toBeNull();
    }
  });

  test('the path is compared after percent-decoding, so an encoded probe is not a bypass', () => {
    const encoded = '/' + PATH.split('').map((c) => `%${c.charCodeAt(0).toString(16)}`).join('') + '/panel';
    expect(matchSecurePath(encoded, PATH)).toEqual(['panel']);
  });

  test('a malformed percent escape is treated as a literal, not an exception', () => {
    expect(() => matchSecurePath('/%zz/panel', PATH)).not.toThrow();
    expect(matchSecurePath('/%zz/panel', PATH)).toBeNull();
  });

  test('the empty path can never match, even against an empty secret', () => {
    expect(matchSecurePath('/', '')).toBeNull();
    expect(matchSecurePath('', '')).toBeNull();
  });
});

describe('generated secrets', () => {
  test('the secure path is long, lowercase-alphanumeric and unambiguous', () => {
    for (let i = 0; i < 50; i++) {
      const p = randomSecurePath();
      expect(p).toMatch(/^[a-z2-9]{24}$/);
      // Characters that get misread when typed off a screen are excluded.
      expect(p).not.toMatch(/[l1o0]/);
    }
  });

  test('secure paths do not repeat', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 500; i++) seen.add(randomSecurePath());
    expect(seen.size).toBe(500);
  });

  test('randomToken is URL-safe and unique', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const t = randomToken(24);
      expect(t).toMatch(/^[A-Za-z0-9_-]+$/);
      seen.add(t);
    }
    expect(seen.size).toBe(200);
  });
});

describe('sessions', () => {
  test('a freshly issued session verifies', async () => {
    const s = secrets();
    expect(await verifySession(s, await issueSession(s))).toBe(true);
  });

  test('a session signed with a different key does not verify', async () => {
    const a = secrets();
    const b = secrets({ sessionKey: 'a-completely-different-session-key' });
    expect(await verifySession(b, await issueSession(a))).toBe(false);
  });

  test('a tampered payload does not verify', async () => {
    const s = secrets();
    const token = await issueSession(s);
    const [body, sig] = token.split('.');
    expect(await verifySession(s, `${body}x.${sig}`)).toBe(false);
    expect(await verifySession(s, `${body}.${sig}x`)).toBe(false);
  });

  test('an expired session does not verify', async () => {
    const s = secrets();
    // Forge a payload that expired an hour ago, signed with the real key.
    const expired = JSON.stringify({ sub: 'admin', exp: Math.floor(Date.now() / 1000) - 3600 });
    const body = Buffer.from(expired).toString('base64url');
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(s.sessionKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = Buffer.from(
      new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body))),
    ).toString('base64url');
    expect(await verifySession(s, `${body}.${sig}`)).toBe(false);
  });

  test('garbage and absent tokens do not verify', async () => {
    const s = secrets();
    for (const t of [null, '', 'x', 'a.b', '....', 'not-base64.not-base64']) {
      expect(await verifySession(s, t)).toBe(false);
    }
  });

  test('cookie helpers set HttpOnly, Secure and SameSite', () => {
    const header = sessionCookieHeader('tok');
    expect(header).toContain('HttpOnly');
    expect(header).toContain('Secure');
    expect(header).toContain('SameSite=Strict');
    expect(clearSessionCookie()).toContain('Max-Age=0');
  });

  test('readCookie finds the session among others', () => {
    const req = new Request('https://x.example/', {
      headers: { Cookie: `other=1; ${SESSION_COOKIE}=abc.def; third=2` },
    });
    expect(readCookie(req, SESSION_COOKIE)).toBe('abc.def');
    expect(readCookie(req, 'missing')).toBeNull();
  });
});

describe('password check', () => {
  test('accepts the right password and rejects everything else', () => {
    const s = secrets();
    expect(checkPassword(s, 'correct-horse-battery')).toBe(true);
    expect(checkPassword(s, 'correct-horse-batter')).toBe(false);
    expect(checkPassword(s, 'Correct-Horse-Battery')).toBe(false);
    expect(checkPassword(s, '')).toBe(false);
  });

  test('an unset password never authenticates, not even with the empty string', () => {
    const s = secrets({ adminHash: '' });
    expect(checkPassword(s, '')).toBe(false);
    expect(checkPassword(s, 'anything')).toBe(false);
  });

  test('the same password under a different salt yields a different hash', () => {
    expect(hashPassword('salt-a', 'pw')).not.toBe(hashPassword('salt-b', 'pw'));
  });
});

describe('timingSafeEqual', () => {
  test('is correct for equal, different and different-length inputs', () => {
    expect(timingSafeEqual('abc', 'abc')).toBe(true);
    expect(timingSafeEqual('abc', 'abd')).toBe(false);
    expect(timingSafeEqual('abc', 'abcd')).toBe(false);
    expect(timingSafeEqual('', '')).toBe(true);
    expect(timingSafeEqual('', 'a')).toBe(false);
  });
});

describe('config migration', () => {
  test('an empty stored config becomes a complete one', () => {
    const cfg = migrateConfig(null);
    expect(cfg.routing.bypassIran).toBe(true);
    expect(cfg.warp.endpoints.length).toBeGreaterThan(0);
    expect(cfg.backend.enabled).toBe(false);
    expect(cfg.fragment.enabled).toBe(false);
  });

  test('a partial stored config keeps its values and gains the missing ones', () => {
    const cfg = migrateConfig({
      vlessUUID: 'kept',
      routing: { blockPorn: true } as never,
      backend: { enabled: true, url: 'https://vps.example/ws' } as never,
    });
    expect(cfg.vlessUUID).toBe('kept');
    expect(cfg.routing.blockPorn).toBe(true);
    // Defaults survive alongside the override.
    expect(cfg.routing.bypassIran).toBe(true);
    expect(cfg.backend.enabled).toBe(true);
    expect(cfg.backend.fallbackToEdge).toBe(true);
  });
});
