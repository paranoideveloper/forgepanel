import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import UsersView from './UsersView.svelte';
import { DEFAULT_PRESENCE_TTL_SECONDS, setPresenceTtlSeconds } from '$lib/presence';

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

// The subscription dialog offered v2ray, Clash and sing-box, hardcoded in the
// component. The endpoint renders ten: Surge, Loon, Quantumult X, Clash.Meta,
// Xray JSON, plain links and a JSON dump were all complete renderers reachable
// only by typing the URL by hand, which no operator would guess to do.
describe('UsersView subscription formats', () => {
  beforeEach(() => {
    stubApi();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  async function openSubDialog(formats?: string[]) {
    const settings = formats ? { ...subSettings, formats } : subSettings;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'POST') return { ok: true, json: async () => ({}) } as Response;
      const table: Record<string, any> = {
        '/api/admin/users': [user],
        '/api/admin/groups': [],
        '/api/admin/inbounds': [],
        '/api/admin/settings/subscription': settings,
        '/api/admin/users/7/sub-requests': {
          items: [{ created_at: '2026-08-30T10:00:00Z', format: 'sing-box', user_agent: 'sing-box 1.9.0', ip: '203.0.113.9' }],
          total: 1,
          limit: 50,
          offset: 0,
          last_fetch_at: '2026-08-30T10:00:00Z',
          last_user_agent: 'sing-box 1.9.0'
        }
      };
      return { ok: true, json: async () => table[String(url)] ?? {} } as Response;
    };
    render(UsersView);
    await screen.findByText('alice');
    await fireEvent.click(screen.getByTestId('open-sub'));
    return (await screen.findByTestId('sub-format')) as HTMLSelectElement;
  }

  it('offers every format the server says it can render', async () => {
    const sel = await openSubDialog([
      'v2ray', 'clash', 'clash-meta', 'sing-box', 'xray',
      'surge', 'loon', 'quantumultx', 'links', 'json'
    ]);
    const values = [...sel.options].map((o) => o.value);
    expect(values).toEqual([
      'v2ray', 'clash', 'clash-meta', 'sing-box', 'xray',
      'surge', 'loon', 'quantumultx', 'links', 'json'
    ]);
  });

  it('builds the URL for a format that is not v2ray', async () => {
    const sel = await openSubDialog(['v2ray', 'surge']);
    await fireEvent.change(sel, { target: { value: 'surge' } });
    const link = await screen.findByTestId('sub-url');
    expect(link.textContent).toContain('/sub/tok7/surge');
  });

  // The dialog is also where an operator finds out whether the link has ever been
  // pulled. The endpoint existed with nothing calling it once already; a GET with
  // no body is invisible to the uicontract guard, so this test is the only thing
  // that keeps the fetch wired.
  it('shows the subscription fetch history', async () => {
    await openSubDialog();
    const rows = await screen.findAllByTestId('sub-request-row');
    expect(rows).toHaveLength(1);
    expect(rows[0].textContent).toContain('sing-box 1.9.0');
    expect(rows[0].textContent).toContain('203.0.113.9');
    expect(screen.getByTestId('sub-last-fetch').textContent).toContain('sing-box 1.9.0');
  });

  // A server that predates the formats field must not leave the operator with an
  // empty select and no way to fetch anything at all.
  it('falls back to the three it always had when the server sends no list', async () => {
    const sel = await openSubDialog();
    expect([...sel.options].map((o) => o.value)).toEqual(['v2ray', 'clash', 'sing-box']);
  });
});

// expand_sni, front_clean_ip and clean_ips are read by the subscription
// renderer on every request. Two of them could only be written as a side effect
// of applying a Preset Wizard theme, and the clean-IP list could not be seen at
// all — so an operator who had never run the wizard had no way to reach any of
// them, and one who had could not change them without running it again.
describe('UsersView subscription output settings', () => {
  function stub(settings: any) {
    const posts: any[] = [];
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'POST') {
        posts.push(JSON.parse(opts.body ?? '{}'));
        return { ok: true, json: async () => ({}) } as Response;
      }
      const table: Record<string, any> = {
        '/api/admin/users': [user],
        '/api/admin/groups': [],
        '/api/admin/inbounds': [],
        '/api/admin/settings/subscription': settings
      };
      return { ok: true, json: async () => table[String(url)] ?? {} } as Response;
    };
    return posts;
  }

  afterEach(() => vi.restoreAllMocks());

  it('renders the three settings the renderer reads', async () => {
    stub({ ...subSettings, expand_sni: true, front_clean_ip: false, clean_ips: '104.16.0.1' });
    render(UsersView);
    await screen.findByText('alice');
    expect(((await screen.findByTestId('expand-sni')) as HTMLInputElement).checked).toBe(true);
    expect((screen.getByTestId('front-clean-ip') as HTMLInputElement).checked).toBe(false);
    expect((screen.getByTestId('clean-ips') as HTMLInputElement).value).toBe('104.16.0.1');
  });

  it('sends them on save', async () => {
    const posts = stub({ ...subSettings, expand_sni: true, front_clean_ip: false, clean_ips: '' });
    render(UsersView);
    await screen.findByText('alice');
    await fireEvent.click(await screen.findByTestId('expand-sni'));
    await fireEvent.input(screen.getByTestId('clean-ips'), { target: { value: '104.17.0.1' } });
    await fireEvent.click(screen.getByTestId('save-sub-settings'));
    await waitFor(() => expect(posts.length).toBeGreaterThan(0));
    expect(posts[0]).toMatchObject({ expand_sni: false, front_clean_ip: false, clean_ips: '104.17.0.1' });
  });

  // Turning fronting on with no addresses configured is a setting that silently
  // does nothing — the exact shape of defect this whole card exists to end.
  it('says fanning out over clean IPs needs a list', async () => {
    stub({ ...subSettings, expand_sni: true, front_clean_ip: true, clean_ips: '' });
    render(UsersView);
    await screen.findByText('alice');
    expect(await screen.findByTestId('clean-ip-empty')).toBeTruthy();
  });

  it('does not nag once the list has addresses', async () => {
    stub({ ...subSettings, expand_sni: true, front_clean_ip: true, clean_ips: '104.16.0.1' });
    render(UsersView);
    await screen.findByText('alice');
    await screen.findByTestId('clean-ips');
    expect(screen.queryByTestId('clean-ip-empty')).toBeNull();
  });
});

// The presence dot answers "is this user online" — the same question the Online
// screen answers — and it used to answer it with its own three-minute window
// while the backend expires presence after two. A user idle for 2m30s was green
// here and already gone from Online.
describe('UsersView presence dot', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    setPresenceTtlSeconds(DEFAULT_PRESENCE_TTL_SECONDS);
  });

  function stubUsers(rows: any[]) {
    (globalThis as any).fetch = async (url: string) => {
      const table: Record<string, any> = {
        '/api/admin/users': rows,
        '/api/admin/groups': [],
        '/api/admin/inbounds': [],
        '/api/admin/settings/subscription': subSettings
      };
      return { ok: true, json: async () => table[String(url)] ?? {} } as Response;
    };
  }

  it('uses the shared presence window, not a longer one of its own', async () => {
    const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();
    stubUsers([
      { ...user, id: 7, username: 'alice', last_seen_at: ago(30) },
      // 150s is inside the old local three-minute window and outside the shared
      // two-minute one. This row is the whole disagreement.
      { ...user, id: 8, username: 'bob', last_seen_at: ago(150) },
      { ...user, id: 9, username: 'carol', last_seen_at: null }
    ]);

    render(UsersView);
    await screen.findByText('alice');

    expect(screen.getByTestId('presence-7').className).toContain('online');
    expect(screen.getByTestId('presence-8').className).not.toContain('online');
    expect(screen.getByTestId('presence-9').className).not.toContain('online');
  });

  it('widens with the window the server published', async () => {
    // The Online screen hands the server's ttl_seconds to the shared module;
    // this row must follow it rather than stay pinned to a compiled-in number.
    // 400s is outside both the shared default AND the three-minute window this
    // view used to carry, so only a dot that actually follows the server value
    // shows bob as online.
    setPresenceTtlSeconds(600);
    const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();
    stubUsers([{ ...user, id: 8, username: 'bob', last_seen_at: ago(400) }]);

    render(UsersView);
    await screen.findByText('bob');

    expect(screen.getByTestId('presence-8').className).toContain('online');
  });
});

// The subscription card writes nine settings in one request, and the panel now
// refuses that request per key with a reason for each. Dropping the reasons on
// the floor and showing one toast leaves an operator staring at nine inputs
// knowing only that "something" was invalid — and the toast is gone before they
// finish reading it.
describe('UsersView subscription settings refusal', () => {
  function stubRefusal(fields: Record<string, string>) {
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'POST') {
        return {
          ok: false,
          status: 400,
          json: async () => ({ error: 'settings: invalid value(s)', fields })
        } as Response;
      }
      const table: Record<string, any> = {
        '/api/admin/users': [user],
        '/api/admin/groups': [],
        '/api/admin/inbounds': [],
        '/api/admin/settings/subscription': subSettings
      };
      return { ok: true, json: async () => table[String(url)] ?? {} } as Response;
    };
  }

  it('names each refused key and why, under the card that owns it', async () => {
    stubRefusal({
      sub_routing_preset: '"nonsense" is not one of: iran, full, block, off',
      sub_front_domain: '"not a domain" is not a hostname'
    });

    render(UsersView);
    await screen.findByTestId('sub-settings');
    await fireEvent.click(screen.getByTestId('save-sub-settings'));

    const subs = await screen.findByTestId('sub-settings-errors');
    expect(subs.textContent).toContain('sub_routing_preset');
    expect(subs.textContent).toContain('is not one of');
    // The fronting knobs live on the wizard card, so their refusal belongs there
    // and not in a list under a card that does not show the input.
    expect(subs.textContent).not.toContain('sub_front_domain');

    const front = await screen.findByTestId('front-settings-errors');
    expect(front.textContent).toContain('sub_front_domain');
    expect(front.textContent).toContain('is not a hostname');
  });

  it('clears the previous refusal when the next save succeeds', async () => {
    stubRefusal({ sub_routing_preset: 'nope' });
    render(UsersView);
    await screen.findByTestId('sub-settings');
    await fireEvent.click(screen.getByTestId('save-sub-settings'));
    await screen.findByTestId('sub-settings-errors');

    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'POST') return { ok: true, json: async () => ({ ok: true }) } as Response;
      return { ok: true, json: async () => ({}) } as Response;
    };
    await fireEvent.click(screen.getByTestId('save-sub-settings'));
    await waitFor(() => expect(screen.queryByTestId('sub-settings-errors')).toBeNull());
  });
});
