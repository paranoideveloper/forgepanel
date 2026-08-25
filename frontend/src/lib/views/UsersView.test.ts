import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import UsersView from './UsersView.svelte';

// Credential rotation. The API has always taken three independent flags and the
// panel sent all three every time, so an operator who only wanted to hand out a
// fresh subscription link also rotated the UUID and the password — breaking
// every config the user had already imported. These tests exist so that cannot
// come back silently.

const user = {
  id: 7,
  username: 'alice',
  uuid: 'u-7',
  sub_token: 'tok7',
  group_id: 0,
  data_limit: 0,
  used_traffic: 0,
  status: 'active'
};

const subSettings = {
  routing_preset: 'default',
  fragment: false,
  presets: ['default'],
  name_template: '',
  pattern: 'off',
  pattern_modes: ['off'],
  front_mode: 'none',
  front_modes: ['none'],
  fancy_themes: []
};

function stubApi(onPost?: (url: string, body: any) => any) {
  (globalThis as any).fetch = async (url: string, opts?: any) => {
    if (opts?.method === 'POST') {
      const body = opts.body ? JSON.parse(opts.body) : {};
      const res = onPost?.(url, body);
      return { ok: true, json: async () => res ?? {} } as Response;
    }
    const path = String(url);
    const table: Record<string, any> = {
      '/api/admin/users': [user],
      '/api/admin/groups': [],
      '/api/admin/inbounds': [],
      '/api/admin/settings/subscription': subSettings
    };
    return { ok: true, json: async () => table[path] ?? {} } as Response;
  };
}

async function openRotateDialog() {
  render(UsersView);
  await screen.findByText('alice');
  await fireEvent.click(screen.getByTestId('rotate'));
  return screen.findByTestId('rotate-confirm');
}

describe('UsersView device limit', () => {
  beforeEach(() => {
    (globalThis as any).confirm = () => true;
  });

  it('sends the device limit when saving a user', async () => {
    let patched: any = null;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'PATCH') {
        patched = JSON.parse(opts.body);
        return { ok: true, json: async () => ({}) } as Response;
      }
      if (opts?.method === 'PUT') return { ok: true, json: async () => ({}) } as Response;
      const table: Record<string, any> = {
        '/api/admin/users': [{ ...user, ip_limit: 2 }],
        '/api/admin/groups': [],
        '/api/admin/inbounds': [],
        '/api/admin/settings/subscription': subSettings
      };
      if (String(url).includes('/admin/users/7')) return { ok: true, json: async () => ({ assignments: { direct: [], inherited: [] } }) } as Response;
      return { ok: true, json: async () => table[String(url)] ?? {} } as Response;
    };

    render(UsersView);
    await screen.findByText('alice');
    await fireEvent.click(screen.getByTestId('manage-user'));

    const field = (await screen.findByTestId('ip-limit')) as HTMLInputElement;
    // The stored value has to come BACK into the form, or saving anything else
    // about the user silently resets their limit to zero.
    expect(field.value).toBe('2');

    await fireEvent.input(field, { target: { value: '4' } });
    await fireEvent.click(screen.getByTestId('save-manage'));

    await vi.waitFor(() => expect(patched).not.toBeNull());
    // The field existed and was editable for its whole life while nothing read
    // it. If the UI stops sending it, it goes back to being decorative.
    expect(patched.ip_limit).toBe(4);
  });

  it('shows a held account as held, without lying about its status', async () => {
    const held = {
      ...user,
      ip_limit: 1,
      ip_limited_until: new Date(Date.now() + 5 * 60_000).toISOString()
    };
    (globalThis as any).fetch = async (url: string) => {
      const table: Record<string, any> = {
        '/api/admin/users': [held],
        '/api/admin/groups': [],
        '/api/admin/inbounds': [],
        '/api/admin/settings/subscription': subSettings
      };
      return { ok: true, json: async () => table[String(url)] ?? {} } as Response;
    };

    render(UsersView);
    expect(await screen.findByTestId('ip-held')).toBeTruthy();
    // Status stays "active" because the hold is transient and self-clearing.
    // An operator seeing only "active" on an account the panel is deliberately
    // refusing has no way to explain the outage.
    expect(screen.getByText('active')).toBeTruthy();
  });

  it('does not mark an expired hold as held', async () => {
    const past = { ...user, ip_limit: 1, ip_limited_until: new Date(Date.now() - 60_000).toISOString() };
    (globalThis as any).fetch = async (url: string) => {
      const table: Record<string, any> = {
        '/api/admin/users': [past],
        '/api/admin/groups': [],
        '/api/admin/inbounds': [],
        '/api/admin/settings/subscription': subSettings
      };
      return { ok: true, json: async () => table[String(url)] ?? {} } as Response;
    };
    render(UsersView);
    await screen.findByText('alice');
    // The cooldown ends on its own; showing it forever would have operators
    // hunting a lockout that is not happening.
    expect(screen.queryByTestId('ip-held')).toBeNull();
  });
});

describe('UsersView credential rotation', () => {
  beforeEach(() => {
    (globalThis as any).confirm = () => true;
    Object.defineProperty(globalThis.navigator, 'clipboard', {
      value: { writeText: vi.fn(async () => {}) },
      configurable: true
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('rotates ONLY the subscription token by default', async () => {
    let posted: any = null;
    stubApi((url, body) => {
      if (url.includes('reset-credentials')) posted = body;
      return { sub_url: 'https://panel.example/sub/new' };
    });

    const confirmBtn = await openRotateDialog();
    await fireEvent.click(confirmBtn);

    // The whole point: the narrow operation must be the default, because it is
    // the only one that does not invalidate configs already in people's hands.
    expect(posted).toEqual({ uuid: false, password: false, sub_token: true });
  });

  it('sends the wider flags only when they are actually ticked', async () => {
    let posted: any = null;
    stubApi((url, body) => {
      if (url.includes('reset-credentials')) posted = body;
      return { sub_url: 'https://panel.example/sub/new' };
    });

    const confirmBtn = await openRotateDialog();
    await fireEvent.click(screen.getByTestId('rotate-uuid'));
    await fireEvent.click(confirmBtn);

    expect(posted).toEqual({ uuid: true, password: false, sub_token: true });
  });

  it('refuses to submit when nothing is selected', async () => {
    let called = false;
    stubApi((url) => {
      if (url.includes('reset-credentials')) called = true;
      return {};
    });

    const confirmBtn = await openRotateDialog();
    await fireEvent.click(screen.getByTestId('rotate-sub')); // untick the default

    // The API rejects an empty request with "specify at least one of ...".
    // Sending it anyway would surface that as a failure the operator caused by
    // using the dialog as designed.
    expect((confirmBtn as HTMLButtonElement).disabled).toBe(true);
    await fireEvent.click(confirmBtn);
    expect(called).toBe(false);
  });

  it('hands back the new subscription link instead of making it be hunted for', async () => {
    stubApi(() => ({ sub_url: 'https://panel.example/sub/new' }));

    const confirmBtn = await openRotateDialog();
    await fireEvent.click(confirmBtn);

    // A rotation whose new URL is not surfaced is a rotation where the old link
    // keeps getting sent out. Awaited: the copy happens after the POST resolves,
    // and asserting synchronously would pass or fail on microtask ordering.
    await vi.waitFor(() =>
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith('https://panel.example/sub/new')
    );
  });

  it('still reports success when the clipboard is unavailable', async () => {
    Object.defineProperty(globalThis.navigator, 'clipboard', {
      value: {
        writeText: async () => {
          throw new Error('denied');
        }
      },
      configurable: true
    });
    let posted: any = null;
    stubApi((url, body) => {
      if (url.includes('reset-credentials')) posted = body;
      return { sub_url: 'https://panel.example/sub/new' };
    });

    const confirmBtn = await openRotateDialog();
    await fireEvent.click(confirmBtn);
    await vi.waitFor(() => expect(posted).not.toBeNull());

    // Clipboard access is denied in plenty of ordinary contexts. The rotation
    // still happened, and reporting it as a failure would push the operator to
    // rotate a second time.
    expect(posted).toEqual({ uuid: false, password: false, sub_token: true });
  });
});
