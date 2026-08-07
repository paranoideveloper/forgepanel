import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import Page from './+page.svelte';

describe('Root Page Component', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('renders login screen when unauthenticated and submits credentials', async () => {
    let loginCalled = false;
    (globalThis as any).fetch = async (url: string) => {
      if (url.includes('/login')) {
        loginCalled = true;
        return {
          ok: true,
          json: async () => ({ access_token: 'jwt-token-123', refresh_token: 'r' })
        } as Response;
      }
      return {
        ok: true,
        json: async () => ({ status: 'healthy', version: '1.0.0', nodes_online: 1, nodes_total: 1 })
      } as Response;
    };

    render(Page);

    expect(screen.getByText('ForgePanel')).toBeTruthy();

    const uInput = screen.getByLabelText('Username');
    const pInput = screen.getByLabelText('Password');

    await fireEvent.input(uInput, { target: { value: 'admin' } });
    await fireEvent.input(pInput, { target: { value: 'secret' } });

    const submitBtn = screen.getByText('Sign In');
    await fireEvent.click(submitBtn);

    expect(loginCalled).toBe(true);
  });
});
