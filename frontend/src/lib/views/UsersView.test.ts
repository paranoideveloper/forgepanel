import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import UsersView from './UsersView.svelte';

describe('UsersView Component', () => {
  beforeEach(() => {
    (globalThis as any).confirm = () => true;
    (globalThis as any).navigator = {
      clipboard: {
        writeText: async () => {}
      }
    };
  });

  it('loads and displays user accounts', async () => {
    (globalThis as any).fetch = async (url: string) => {
      if (url.includes('/admin/users')) {
        return {
          ok: true,
          json: async () => [
            { id: 1, username: 'alice', sub_token: 'sub12345678', enabled: true, group_id: 1, notes: 'VIP' }
          ]
        } as Response;
      }
      if (url.includes('/admin/groups')) {
        return {
          ok: true,
          json: async () => [
            { id: 1, name: 'VIP Group' }
          ]
        } as Response;
      }
      return { ok: true, json: async () => ({}) } as Response;
    };

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
    let postCalled = false;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'POST') {
        postCalled = true;
        return { ok: true, json: async () => ({ id: 2, username: 'bob' }) } as Response;
      }
      return { ok: true, json: async () => [] } as Response;
    };

    render(UsersView);

    const input = screen.getByPlaceholderText('Username');
    await fireEvent.input(input, { target: { value: 'bob' } });

    const createBtn = screen.getByText('Create User');
    await fireEvent.click(createBtn);

    expect(postCalled).toBe(true);
  });

  it('toggles, rotates token, and deletes a user', async () => {
    let deleteCalled = false;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (url.includes('/rotate-token')) {
        return { ok: true, json: async () => ({ sub_token: 'newtoken' }) } as Response;
      }
      if (opts?.method === 'DELETE') {
        deleteCalled = true;
        return { ok: true, json: async () => ({ deleted: 1 }) } as Response;
      }
      if (opts?.method === 'PUT') {
        return { ok: true, json: async () => ({ id: 1, enabled: false }) } as Response;
      }
      return {
        ok: true,
        json: async () => [
          { id: 1, username: 'alice', sub_token: 'sub12345678', enabled: true }
        ]
      } as Response;
    };

    render(UsersView);

    const disableBtn = await screen.findByText('Disable');
    await fireEvent.click(disableBtn);

    const rotateBtn = await screen.findByText('Rotate');
    await fireEvent.click(rotateBtn);

    const deleteBtn = await screen.findByText('Delete');
    await fireEvent.click(deleteBtn);

    expect(deleteCalled).toBe(true);
  });

  it('opens subscription link modal and copies URL with format toggles', async () => {
    let copyCalled = false;
    (globalThis as any).navigator.clipboard.writeText = async () => { copyCalled = true; };
    (globalThis as any).fetch = async () => ({
      ok: true,
      json: async () => [
        { id: 1, username: 'alice', sub_token: 'sub12345678', enabled: true }
      ]
    } as Response);

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

    expect(copyCalled).toBe(true);
  });
});
