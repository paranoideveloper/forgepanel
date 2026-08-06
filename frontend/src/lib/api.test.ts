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

    await expect(apiFetch('/test')).rejects.toEqual({
      message: 'Invalid input',
      status: 400
    });
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
