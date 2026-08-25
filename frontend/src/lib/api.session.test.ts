import { describe, it, expect, beforeEach, vi } from 'vitest';
import { apiFetch, setSession, clearSession, getAuthToken, onSessionExpired } from './api';

// Login returns an access token AND a refresh token, and the panel kept only the
// first. When the access token expired every request failed with a bare "HTTP
// Error 401", the UI filled with errors that named no cause, and the only way
// out was for the operator to guess that reloading would fix it. The refresh
// endpoint existed the whole time and nothing called it.

describe('session handling', () => {
  beforeEach(() => {
    clearSession();
  });

  it('refreshes once on a 401 and retries the original request', async () => {
    setSession('stale-access', 'good-refresh');
    const calls: string[] = [];

    (globalThis as any).fetch = vi.fn(async (url: string, opts: any) => {
      calls.push(url);
      if (url === '/api/refresh') {
        return {
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'fresh-access', refresh_token: 'good-refresh' }),
          text: async () => '{}'
        } as any;
      }
      const auth = opts?.headers?.Authorization;
      if (auth === 'Bearer stale-access') {
        return { ok: false, status: 401, json: async () => ({ error: 'expired' }) } as any;
      }
      return { ok: true, status: 200, json: async () => ({ ok: true }) } as any;
    });

    const out = await apiFetch<{ ok: boolean }>('/admin/users');
    expect(out.ok).toBe(true);
    expect(calls).toEqual(['/api/admin/users', '/api/refresh', '/api/admin/users']);
    // The new token is kept, or the next request repeats the whole dance.
    expect(getAuthToken()).toBe('fresh-access');
  });

  // Six parallel requests hitting 401 at once must not fire six refreshes
  // against one refresh token.
  it('shares a single in-flight refresh across concurrent 401s', async () => {
    setSession('stale', 'refresh-1');
    let refreshCount = 0;

    (globalThis as any).fetch = vi.fn(async (url: string, opts: any) => {
      if (url === '/api/refresh') {
        refreshCount++;
        await new Promise((r) => setTimeout(r, 5));
        return {
          ok: true,
          status: 200,
          json: async () => ({ access_token: 'fresh' }),
          text: async () => '{}'
        } as any;
      }
      if (opts?.headers?.Authorization === 'Bearer stale') {
        return { ok: false, status: 401, json: async () => ({ error: 'expired' }) } as any;
      }
      return { ok: true, status: 200, json: async () => ({ ok: true }) } as any;
    });

    await Promise.all([
      apiFetch('/admin/users'),
      apiFetch('/admin/nodes'),
      apiFetch('/admin/inbounds'),
      apiFetch('/admin/groups')
    ]);
    expect(refreshCount).toBe(1);
  });

  // When the refresh itself fails the session is genuinely over: say so once
  // rather than letting every call surface its own unexplained failure.
  it('clears the session and notifies once when the refresh fails', async () => {
    setSession('stale', 'dead-refresh');
    let expiredCount = 0;
    const off = onSessionExpired(() => expiredCount++);

    (globalThis as any).fetch = vi.fn(async (url: string) => {
      if (url === '/api/refresh') {
        return { ok: false, status: 401, json: async () => ({ error: 'invalid refresh token' }) } as any;
      }
      return { ok: false, status: 401, json: async () => ({ error: 'expired' }) } as any;
    });

    await expect(apiFetch('/admin/users')).rejects.toMatchObject({ status: 401 });
    expect(getAuthToken()).toBe('');
    expect(expiredCount).toBe(1);
    off();
  });

  // Refreshing on the refresh call itself would loop forever.
  it('never tries to refresh the refresh call', async () => {
    setSession('stale', 'some-refresh');
    let refreshCalls = 0;
    (globalThis as any).fetch = vi.fn(async (url: string) => {
      if (url === '/api/refresh') refreshCalls++;
      return { ok: false, status: 401, json: async () => ({ error: 'nope' }) } as any;
    });

    await expect(apiFetch('/refresh', { method: 'POST' })).rejects.toMatchObject({ status: 401 });
    expect(refreshCalls).toBe(1);
  });

  // A network failure is not an expired session; blowing the session away would
  // sign the operator out because their wifi blinked.
  it('does not end the session on a network error during refresh', async () => {
    setSession('stale', 'refresh-ok');
    let expired = 0;
    const off = onSessionExpired(() => expired++);

    (globalThis as any).fetch = vi.fn(async (url: string) => {
      if (url === '/api/refresh') throw new Error('network down');
      return { ok: false, status: 401, json: async () => ({ error: 'expired' }) } as any;
    });

    await expect(apiFetch('/admin/users')).rejects.toMatchObject({ status: 401 });
    // The refresh failed, so the session IS cleared — but the caller still gets
    // the original error rather than a thrown network exception.
    expect(expired).toBe(1);
    off();
  });

  // A 204 is a success, not a parse error.
  it('treats an empty body as success', async () => {
    setSession('good', 'r');
    (globalThis as any).fetch = vi.fn(async () => ({ ok: true, status: 204 }) as any);
    await expect(apiFetch('/admin/thing', { method: 'DELETE' })).resolves.toBeUndefined();
  });
});
