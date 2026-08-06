import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import UsersView from './UsersView.svelte';

describe('UsersView Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.stubGlobal('confirm', () => true);
    vi.stubGlobal('navigator', {
      clipboard: {
        writeText: vi.fn().mockResolvedValue(undefined)
      }
    });
  });

  it('loads and displays user accounts', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.includes('/admin/users')) {
        return Promise.resolve({
          ok: true,
          json: async () => [
            { id: 1, username: 'alice', sub_token: 'sub12345678', enabled: true, group_id: 1, notes: 'VIP' }
          ]
        });
      }
      if (url.includes('/admin/usergroups')) {
        return Promise.resolve({
          ok: true,
          json: async () => [
            { id: 1, name: 'VIP Group' }
          ]
        });
      }
      return Promise.resolve({ ok: true, json: async () => ({}) });
    }));

    render(UsersView);

    expect(await screen.findByText('alice')).toBeTruthy();
    expect(screen.getAllByText('VIP Group').length).toBeGreaterThan(0);
    expect(screen.getByText('sub12345...')).toBeTruthy();
    expect(screen.getByText('VIP')).toBeTruthy();
  });

  it('validates user creation inputs', async () => {
    render(UsersView);
    const createBtn = screen.getByText('Create User');
    await fireEvent.click(createBtn);
    expect(await screen.findByText('Username is required')).toBeTruthy();
  });

  it('creates new user account', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string, opts?: any) => {
      if (opts?.method === 'POST') {
        return Promise.resolve({ ok: true, json: async () => ({ id: 2, username: 'bob' }) });
      }
      return Promise.resolve({ ok: true, json: async () => [] });
    }));

    render(UsersView);

    const input = screen.getByPlaceholderText('Username');
    await fireEvent.input(input, { target: { value: 'bob' } });

    const createBtn = screen.getByText('Create User');
    await fireEvent.click(createBtn);

    expect(fetch).toHaveBeenCalledWith('/api/admin/users', expect.objectContaining({ method: 'POST' }));
  });

  it('toggles, rotates token, and deletes a user', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string, opts?: any) => {
      if (url.includes('/rotate-token')) {
        return Promise.resolve({ ok: true, json: async () => ({ sub_token: 'newtoken' }) });
      }
      if (opts?.method === 'DELETE') {
        return Promise.resolve({ ok: true, json: async () => ({ deleted: 1 }) });
      }
      if (opts?.method === 'PUT') {
        return Promise.resolve({ ok: true, json: async () => ({ id: 1, enabled: false }) });
      }
      return Promise.resolve({
        ok: true,
        json: async () => [
          { id: 1, username: 'alice', sub_token: 'sub12345678', enabled: true }
        ]
      });
    }));

    render(UsersView);

    const disableBtn = await screen.findByText('Disable');
    await fireEvent.click(disableBtn);

    const rotateBtn = await screen.findByText('Rotate');
    await fireEvent.click(rotateBtn);

    const deleteBtn = await screen.findByText('Delete');
    await fireEvent.click(deleteBtn);

    expect(fetch).toHaveBeenCalledWith('/api/admin/users/1', expect.objectContaining({ method: 'DELETE' }));
  });

  it('opens subscription link modal and copies URL with format toggles', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [
        { id: 1, username: 'alice', sub_token: 'sub12345678', enabled: true }
      ]
    }));

    render(UsersView);

    const subLinkBtn = await screen.findByText('Sub Link');
    await fireEvent.click(subLinkBtn);

    expect(screen.getByText('Subscription Details')).toBeTruthy();

    const clashBtn = screen.getByText('Clash Meta');
    await fireEvent.click(clashBtn);

    const singBoxBtn = screen.getByText('Sing-Box');
    await fireEvent.click(singBoxBtn);

    const copyBtn = screen.getByText('Copy Link');
    await fireEvent.click(copyBtn);

    expect(navigator.clipboard.writeText).toHaveBeenCalled();
  });
});
