import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import AdminsView from './AdminsView.svelte';

// The reseller model was enforced throughout the backend with no way to create a
// second admin, so multi-tenancy was unreachable. These cover the surface that
// makes it usable, and the refusals that keep it safe.

const owner = {
  id: 1, username: 'owner', role: 'owner', disabled: false, two_factor_enabled: true,
  user_quota: 0, traffic_credit: 0, users_owned: 0, traffic_allocated: 0,
  created_at: '2026-01-01T00:00:00Z'
};
const reseller = {
  id: 2, username: 'rs', role: 'reseller', disabled: false, two_factor_enabled: false,
  user_quota: 50, traffic_credit: 10 * 1024 ** 3, users_owned: 12,
  traffic_allocated: 4 * 1024 ** 3, created_at: '2026-02-01T00:00:00Z'
};

describe('AdminsView', () => {
  beforeEach(() => {
    (globalThis as any).confirm = () => true;
  });

  it('lists accounts with their quota usage', async () => {
    (globalThis as any).fetch = async () =>
      ({ ok: true, json: async () => [owner, reseller] }) as Response;

    render(AdminsView);

    // 'owner' also appears as a role <option>, so awaiting that would race the
    // table. Await something only a row renders.
    expect(await screen.findByText('rs')).toBeTruthy();
    // A reseller's headroom is the number an owner actually needs.
    expect(screen.getByText('12 / 50')).toBeTruthy();
    expect(screen.getByText('4 / 10 GB')).toBeTruthy();
  });

  it('creates a reseller with its quota', async () => {
    let posted: any = null;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'POST') {
        posted = JSON.parse(opts.body);
        return { ok: true, json: async () => ({ id: 3 }) } as Response;
      }
      return { ok: true, json: async () => [owner] } as Response;
    };

    render(AdminsView);
    await screen.findByTestId('new-admin-username');

    await fireEvent.input(screen.getByTestId('new-admin-username'), { target: { value: 'newrs' } });
    await fireEvent.input(screen.getByTestId('new-admin-password'), { target: { value: 'hunter2hunter2' } });
    await fireEvent.input(screen.getByTestId('new-admin-quota'), { target: { value: '25' } });
    await fireEvent.click(screen.getByText('Create'));

    expect(posted?.username).toBe('newrs');
    expect(posted?.role).toBe('reseller');
    expect(posted?.user_quota).toBe(25);
  });

  it('refuses a short password before sending anything', async () => {
    let posted = false;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'POST') posted = true;
      return { ok: true, json: async () => [owner] } as Response;
    };

    render(AdminsView);
    await screen.findByTestId('new-admin-username');
    await fireEvent.input(screen.getByTestId('new-admin-username'), { target: { value: 'weak' } });
    await fireEvent.input(screen.getByTestId('new-admin-password'), { target: { value: 'short' } });
    await fireEvent.click(screen.getByText('Create'));

    expect(await screen.findByTestId('create-error')).toBeTruthy();
    expect(posted).toBe(false);
  });

  // Losing the only owner cannot be undone from inside the panel, so the
  // operator has to be told before they try.
  it('warns while there is only one owner', async () => {
    (globalThis as any).fetch = async () =>
      ({ ok: true, json: async () => [owner, reseller] }) as Response;
    render(AdminsView);
    expect(await screen.findByText(/one owner/)).toBeTruthy();
  });

  // A quota of 0 means unlimited, so sending every field on every edit would
  // silently remove limits the operator never touched.
  it('patches only the fields that changed', async () => {
    let patched: any = null;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'PATCH') {
        patched = JSON.parse(opts.body);
        return { ok: true, json: async () => ({}) } as Response;
      }
      return { ok: true, json: async () => [owner, reseller] } as Response;
    };

    render(AdminsView);
    await screen.findByText('rs');
    const editButtons = screen.getAllByText('Edit');
    await fireEvent.click(editButtons[1]); // the reseller

    await fireEvent.change(screen.getByTestId('edit-admin-role'), { target: { value: 'admin' } });
    await fireEvent.click(screen.getByText('Save'));

    expect(patched).toEqual({ role: 'admin' });
    expect(patched.user_quota).toBeUndefined();
  });

  // Orphaned customers belong to nobody: no reseller sees them and nothing can
  // manage them, while they keep being served.
  it('requires a destination before deleting an account that owns customers', async () => {
    let deleted = false;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'DELETE') deleted = true;
      return { ok: true, json: async () => [owner, reseller] } as Response;
    };

    render(AdminsView);
    await screen.findByText('rs');
    const del = screen.getAllByText('Delete');
    await fireEvent.click(del[1]);

    // The dialog must say what is at stake and offer a destination.
    expect(await screen.findByTestId('reassign-target')).toBeTruthy();
    expect(screen.getByText(/belongs to nobody/)).toBeTruthy();
    expect(deleted).toBe(false);

    await fireEvent.click(screen.getByText('Delete account'));
    expect(deleted).toBe(true);
  });
});
