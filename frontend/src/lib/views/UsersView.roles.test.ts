import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import UsersView from './UsersView.svelte';

const user = {
  id: 7, username: 'alice', uuid: 'u-7', sub_token: 'tok7',
  group_id: 3, data_limit: 5 * 1024 ** 3, used_traffic: 1024 ** 3,
  lifetime_traffic: 9 * 1024 ** 3, last_reset_at: '2026-08-01T00:00:00Z',
  status: 'active', ip_limit: 2, reset_strategy: 'no_reset',
  expire_at: '2026-12-31T00:00:00Z', updated_at: '2026-08-01T00:00:00Z',
  telegram_id: 0, note: ''
};
const groups = [{ id: 3, name: 'gold' }, { id: 4, name: 'silver' }];

type Call = { url: string; method: string; body: any };

// world builds a fake backend with a given role, and records every call so a
// test can assert what the view actually sent.
function world(opts: {
  role: string;
  denyGroups?: boolean;
  denySubSettings?: boolean;
  quota?: any;
  deleteGroupConflict?: boolean;
}) {
  const calls: Call[] = [];
  (globalThis as any).localStorage = { getItem: () => 'tok', setItem: () => {}, removeItem: () => {} };
  (globalThis as any).confirm = () => true;
  (globalThis as any).fetch = async (url: string, o: any = {}) => {
    const method = o.method ?? 'GET';
    calls.push({ url: String(url), method, body: o.body ? JSON.parse(o.body) : null });
    const p = String(url);
    const deny = (msg: string, extra: any = {}) =>
      ({ ok: false, status: 403, json: async () => ({ error: msg, ...extra }) } as Response);

    if (p.includes('/admin/quota')) {
      return { ok: true, json: async () => opts.quota ?? { role: opts.role, unlimited: true } } as Response;
    }
    if (p.includes('/admin/groups')) {
      if (method === 'DELETE') {
        if (opts.deleteGroupConflict && !p.includes('?')) {
          return { ok: false, status: 409, json: async () => ({
            error: 'group is in use', code: 'group_in_use', members: [user]
          }) } as Response;
        }
        return { ok: true, json: async () => ({ deleted: true }) } as Response;
      }
      if (opts.denyGroups) return deny('insufficient role');
      return { ok: true, json: async () => groups } as Response;
    }
    if (p.includes('/admin/settings/subscription')) {
      if (opts.denySubSettings) return deny('insufficient role');
      return { ok: true, json: async () => ({ presets: [], pattern_modes: [], front_modes: [], fancy_themes: [] }) } as Response;
    }
    if (p.includes('/admin/users/7')) return { ok: true, json: async () => ({ assignments: { direct: [], inherited: [] } }) } as Response;
    if (p.includes('/admin/users')) return { ok: true, json: async () => [user] } as Response;
    if (p.includes('/admin/inbounds')) return { ok: true, json: async () => [{ id: 11, remark: 'de-reality', protocol: 'vless', port: 443 }] } as Response;
    return { ok: true, json: async () => ({}) } as Response;
  };
  return calls;
}

describe('UsersView and the caller’s role', () => {
  beforeEach(() => {
    (globalThis as any).confirm = () => true;
  });

  it('finishes loading everything a reseller MAY read when an owner-only call is refused', async () => {
    // The defect: /admin/groups and /admin/settings/subscription are
    // owner/admin-only and were awaited INLINE, so for a reseller the 403 threw
    // out of loadData and everything after it was skipped. Users happened to be
    // fetched first so the list still appeared — which is why this was easy to
    // miss — but INBOUNDS never loaded, so the reseller could open a user and
    // find nothing to assign, on top of an "insufficient role" toast for a
    // permission they were never meant to have.
    //
    // Asserting the user row alone would pass either way. The inbound is the
    // part that actually disappeared.
    const calls = world({ role: 'reseller', denyGroups: true, denySubSettings: true });
    render(UsersView);
    await screen.findByText('alice');
    await fireEvent.click(screen.getByTestId('manage-user'));
    expect(await screen.findByText(/de-reality/)).toBeTruthy();
    expect(calls.some((c) => c.url.includes('/admin/inbounds'))).toBe(true);
  });

  it('hides the group controls from a role the API refuses', async () => {
    // Rendering them offers buttons the handler rejects — the UI promising
    // something the API will not do.
    world({ role: 'reseller', denyGroups: true });
    render(UsersView);
    await screen.findByText('alice');
    expect(screen.queryByTestId('new-group')).toBeNull();
  });

  it('shows the group controls to an owner', async () => {
    world({ role: 'owner' });
    render(UsersView);
    await screen.findByText('alice');
    expect(await screen.findByTestId('new-group')).toBeTruthy();
  });

  it('shows a reseller their remaining headroom', async () => {
    // Without it, exhaustion arrives as an opaque 409 quota_exceeded on a
    // create they have already filled in.
    world({
      role: 'reseller',
      quota: { role: 'reseller', unlimited: false, user_quota: 10, users_used: 8,
               users_remaining: 2, traffic_credit: 1024 ** 3, traffic_allocated: 0, traffic_remaining: 1024 ** 3 }
    });
    render(UsersView);
    const strip = await screen.findByTestId('quota-strip');
    expect(strip.textContent).toContain('2');
    expect(strip.textContent).toContain('10');
  });

  it('does not show a quota strip to an unlimited role', async () => {
    world({ role: 'owner', quota: { role: 'owner', unlimited: true, user_quota: 0, users_used: 3, traffic_credit: 0, traffic_allocated: 0 } });
    render(UsersView);
    await screen.findByText('alice');
    expect(screen.queryByTestId('quota-strip')).toBeNull();
  });
});

describe('UsersView save', () => {
  beforeEach(() => {
    (globalThis as any).confirm = () => true;
  });

  it('omits data_limit when it was not touched', async () => {
    // It used to be sent unconditionally. data_limit is outside
    // resellerUserFields, so EVERY reseller edit 422'd on a field the operator
    // had not touched.
    const calls = world({ role: 'reseller' });
    render(UsersView);
    await screen.findByText('alice');
    await fireEvent.click(screen.getByTestId('manage-user'));
    await screen.findByTestId('save-manage');
    await fireEvent.click(screen.getByTestId('save-manage'));

    await waitFor(() => expect(calls.some((c) => c.method === 'PATCH')).toBe(true));
    const patch = calls.find((c) => c.method === 'PATCH')!.body;
    expect('data_limit' in patch).toBe(false);
    expect(patch.status).toBe('active');
  });

  it('sends group_id 0 so a user can be taken out of a group', async () => {
    // 'No group' set mGroupId = undefined, and JSON.stringify DROPS undefined —
    // so the PATCH carried no group_id at all and a user could never leave a
    // group. The control worked; the request simply did not contain it.
    const calls = world({ role: 'owner' });
    render(UsersView);
    await screen.findByText('alice');
    await fireEvent.click(screen.getByTestId('manage-user'));
    const sel = (await screen.findByTestId('manage-group')) as HTMLSelectElement;
    await fireEvent.change(sel, { target: { value: '' } });
    await fireEvent.click(screen.getByTestId('save-manage'));

    await waitFor(() => expect(calls.some((c) => c.method === 'PATCH')).toBe(true));
    const patch = calls.find((c) => c.method === 'PATCH')!.body;
    expect('group_id' in patch).toBe(true);
    expect(patch.group_id).toBe(0);
  });
});

describe('UsersView group delete', () => {
  beforeEach(() => {
    (globalThis as any).confirm = () => true;
  });

  it('asks where the members go instead of surfacing a raw 409', async () => {
    // The backend refuses to guess a disposition and returns 409 group_in_use.
    // The UI offered neither option, so a group with members could not be
    // deleted from the panel at all. Members are never deleted either way.
    const calls = world({ role: 'owner', deleteGroupConflict: true });
    render(UsersView);
    await screen.findByText('alice');
    await fireEvent.click((await screen.findAllByTestId('group-delete'))[0]);

    const confirmBtn = await screen.findByTestId('group-delete-confirm');
    const reassign = (await screen.findByTestId('group-reassign')) as HTMLSelectElement;
    await fireEvent.change(reassign, { target: { value: '4' } });
    await fireEvent.click(confirmBtn);

    await waitFor(() => {
      const d = calls.filter((c) => c.method === 'DELETE');
      expect(d.some((c) => c.url.includes('reassign_to=4'))).toBe(true);
    });
  });
});

describe('UsersView user fields that had no control', () => {
  beforeEach(() => {
    (globalThis as any).confirm = () => true;
  });

  it('sends a sub-gigabyte data limit as bytes, not truncated gigabytes', async () => {
    // The bug with real money behind it: the limit was an int64 of whole GB, so
    // a 500 MB trial arrived as 0 — and 0 means UNLIMITED. The account then
    // moves a hundred gigabytes before anybody notices.
    const calls = world({ role: 'owner' });
    render(UsersView);
    await screen.findByText('alice');
    const limit = (await screen.findByTestId('create-limit')) as HTMLInputElement;
    await fireEvent.input(limit, { target: { value: '0.5' } });
    await fireEvent.input(screen.getByPlaceholderText(/username/i), { target: { value: 'trial' } });
    await fireEvent.click(screen.getByTestId('create-user'));

    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    const body = calls.find((c) => c.method === 'POST')!.body;
    expect(body.data_limit).toBe(Math.round(0.5 * 1024 ** 3));
    expect(body.data_limit).toBeGreaterThan(0);
  });

  it('sends the optimistic-concurrency token so two admins cannot clobber each other', async () => {
    // updated_at was READ and never sent, so the backend's ifUnchanged check
    // never engaged: last write won, and neither admin was told.
    const calls = world({ role: 'owner' });
    render(UsersView);
    await screen.findByText('alice');
    await fireEvent.click(screen.getByTestId('manage-user'));
    await screen.findByTestId('save-manage');
    await fireEvent.click(screen.getByTestId('save-manage'));

    await waitFor(() => expect(calls.some((c) => c.method === 'PATCH')).toBe(true));
    expect(calls.find((c) => c.method === 'PATCH')!.body.updated_at).toBe('2026-08-01T00:00:00Z');
  });

  it('can clear an expiry, which was previously impossible', async () => {
    // expire_at was write-only and relative-only: you could extend an expiry you
    // could not see, and never remove one.
    const calls = world({ role: 'owner' });
    render(UsersView);
    await screen.findByText('alice');
    await fireEvent.click(screen.getByTestId('manage-user'));
    const date = (await screen.findByTestId('manage-expire-at')) as HTMLInputElement;
    expect(date.value).toBe('2026-12-31'); // the current expiry is now visible
    await fireEvent.input(date, { target: { value: '' } });
    await fireEvent.click(screen.getByTestId('save-manage'));

    await waitFor(() => expect(calls.some((c) => c.method === 'PATCH')).toBe(true));
    expect(calls.find((c) => c.method === 'PATCH')!.body.expire_at).toBe('');
  });

  it('sends the reset strategy, telegram id and note', async () => {
    // All three are PATCH-able and validated server-side; two are in the
    // reseller allowlist. None had a control anywhere.
    const calls = world({ role: 'owner' });
    render(UsersView);
    await screen.findByText('alice');
    await fireEvent.click(screen.getByTestId('manage-user'));
    await fireEvent.change(await screen.findByTestId('manage-reset'), { target: { value: 'month' } });
    await fireEvent.input(screen.getByTestId('manage-telegram'), { target: { value: '12345' } });
    await fireEvent.input(screen.getByTestId('manage-note'), { target: { value: 'paid til June' } });
    await fireEvent.click(screen.getByTestId('save-manage'));

    await waitFor(() => expect(calls.some((c) => c.method === 'PATCH')).toBe(true));
    const b = calls.find((c) => c.method === 'PATCH')!.body;
    expect(b.reset_strategy).toBe('month');
    expect(b.telegram_id).toBe(12345);
    expect(b.note).toBe('paid til June');
  });

  it('can revoke a subscription without rotating the credentials', async () => {
    // sub_revoked_at was enforced end to end — a non-nil value empties the node
    // list and drops the user from the edge feed — and NOTHING wrote it, so the
    // whole mechanism was unreachable.
    const calls = world({ role: 'owner' });
    render(UsersView);
    await screen.findByText('alice');
    await fireEvent.click(screen.getByTestId('manage-user'));
    await fireEvent.click(await screen.findByTestId('toggle-sub-revoked'));

    await waitFor(() => expect(calls.some((c) => c.url.includes('/sub-revoked'))).toBe(true));
    const call = calls.find((c) => c.url.includes('/sub-revoked'))!;
    expect(call.body.revoked).toBe(true);
    // Rotating is the other action and must not be involved.
    expect(calls.some((c) => c.url.includes('reset-credentials'))).toBe(false);
  });

  it('shows lifetime traffic alongside the current period', async () => {
    // used_traffic alone is ambiguous once a reset strategy is set: it is the
    // current period only, and the number cannot be read without knowing when
    // that period began.
    world({ role: 'owner' });
    render(UsersView);
    expect(await screen.findByTestId('lifetime')).toBeTruthy();
  });
});
