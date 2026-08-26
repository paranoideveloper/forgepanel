import { describe, it, expect, beforeEach, vi } from 'vitest';
import { setAuthToken, getAuthToken, apiFetch } from './api';

describe('API Client', () => {
  beforeEach(() => {
    localStorage.clear();
    setAuthToken('');
  });

  it('manages auth tokens in localStorage', () => {
    expect(getAuthToken()).toBe('');
    setAuthToken('my-token');
    expect(getAuthToken()).toBe('my-token');
    expect(localStorage.getItem('forge_token')).toBe('my-token');
    setAuthToken('');
    expect(getAuthToken()).toBe('');
    expect(localStorage.getItem('forge_token')).toBeNull();
  });

  it('performs successful GET requests with auth headers', async () => {
    setAuthToken('bearer-123');
    const fakeData = { status: 'ok' };
    
    let calledUrl = '';
    let calledOpts: any = null;
    (globalThis as any).fetch = async (url: string, opts: any) => {
      calledUrl = url;
      calledOpts = opts;
      return {
        ok: true,
        json: async () => fakeData
      } as Response;
    };

    const result = await apiFetch<{ status: string }>('/test');
    expect(result).toEqual(fakeData);
    expect(calledUrl).toBe('/api/test');
    expect(calledOpts.headers['Authorization']).toBe('Bearer bearer-123');
  });

  it('handles HTTP error responses with server error messages', async () => {
    (globalThis as any).fetch = async () => ({
      ok: false,
      status: 400,
      json: async () => ({ error: 'Invalid input' })
    } as unknown as Response);

    await expect(apiFetch('/test')).rejects.toMatchObject({
      message: 'Invalid input',
      status: 400
    });
  });

  it('carries the whole error body, not just its message', async () => {
    // The API answers a refused request with far more than a sentence: `code`
    // for a machine-readable reason, `fields` mapping each rejected field to
    // why, `remediation`, and whatever else the endpoint needs to say
    // (`members` on a group conflict, `missing_scope` on a Cloudflare refusal).
    // Collapsing it to one string meant a caller could only ever show a toast —
    // no per-field errors under the inputs, and no way to offer the choice the
    // backend is explicitly asking for.
    (globalThis as any).fetch = async () => ({
      ok: false,
      status: 409,
      json: async () => ({
        error: 'group is in use',
        code: 'group_in_use',
        members: [{ id: 7, username: 'alice' }],
        fields: { name: 'already taken' },
        remediation: 'pass ?reassign_to=<group id>'
      })
    } as unknown as Response);

    try {
      await apiFetch('/test');
      throw new Error('should have rejected');
    } catch (e: any) {
      expect(e.code).toBe('group_in_use');
      expect(e.fields).toEqual({ name: 'already taken' });
      expect(e.remediation).toContain('reassign_to');
      expect((e.body?.members as any[])?.[0]?.username).toBe('alice');
    }
  });

  it('handles HTTP error responses when json parsing fails', async () => {
    (globalThis as any).fetch = async () => ({
      ok: false,
      status: 500,
      json: async () => { throw new Error('Bad JSON'); }
    } as unknown as Response);

    await expect(apiFetch('/test')).rejects.toEqual({
      message: 'HTTP Error 500',
      status: 500
    });
  });
});
