import { describe, it, expect, beforeEach, vi } from 'vitest';
import { setAuthToken, getAuthToken, apiFetch } from './api';

describe('API Client', () => {
  beforeEach(() => {
    localStorage.clear();
    setAuthToken('');
    vi.restoreAllMocks();
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
    
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => fakeData
    }));

    const result = await apiFetch<{ status: string }>('/test');
    expect(result).toEqual(fakeData);
    expect(fetch).toHaveBeenCalledWith('/api/test', expect.objectContaining({
      headers: expect.objectContaining({
        'Authorization': 'Bearer bearer-123',
        'Content-Type': 'application/json'
      })
    }));
  });

  it('handles HTTP error responses with server error messages', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      json: async () => ({ error: 'Invalid input' })
    }));

    await expect(apiFetch('/test')).rejects.toEqual({
      message: 'Invalid input',
      status: 400
    });
  });

  it('handles HTTP error responses when json parsing fails', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => { throw new Error('Bad JSON'); }
    }));

    await expect(apiFetch('/test')).rejects.toEqual({
      message: 'HTTP Error 500',
      status: 500
    });
  });
});
