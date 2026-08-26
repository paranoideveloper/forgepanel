import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import UsersView from './UsersView.svelte';

const user = {
  id: 7, username: 'alice', uuid: 'u-7', sub_token: 'tok7',
  group_id: 3, data_limit: 5 * 1024 ** 3, used_traffic: 0, status: 'active', ip_limit: 2
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
