import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import Page from './+page.svelte';

describe('Root Page Component', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it('renders login screen when unauthenticated and submits credentials', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.includes('/auth/login')) {
        return Promise.resolve({
          ok: true,
          json: async () => ({ token: 'jwt-token-123' })
        });
      }
      return Promise.resolve({
        ok: true,
        json: async () => ({ status: 'healthy', version: '1.0.0', nodes_online: 1, nodes_total: 1 })
      });
    }));

    render(Page);

    expect(screen.getByText('ForgePanel')).toBeTruthy();

    const uInput = screen.getByLabelText('Username');
    const pInput = screen.getByLabelText('Password');

    await fireEvent.input(uInput, { target: { value: 'admin' } });
    await fireEvent.input(pInput, { target: { value: 'secret' } });

    const submitBtn = screen.getByText('Sign In');
    await fireEvent.click(submitBtn);

    expect(fetch).toHaveBeenCalledWith('/api/auth/login', expect.objectContaining({
      method: 'POST'
    }));
  });
});
