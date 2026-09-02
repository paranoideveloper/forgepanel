import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import SystemHealthView from './SystemHealthView.svelte';

const toasts: Array<{ msg: string; kind: string }> = [];
vi.mock('$lib/components/Toast.svelte', async () => {
  const actual = await vi.importActual<any>('$lib/components/Toast.svelte');
  return { ...actual, showToast: (msg: string, kind = 'info') => { toasts.push({ msg, kind }); } };
});

// The bot token was read once from FORGEPANEL_TELEGRAM_TOKEN at process start
// and nowhere else, so configuring alerts meant editing a compose file and
// restarting the panel — for the feature whose entire purpose is telling an
// operator about things that happen while they are not looking.

function api(settings: any, onPost?: (url: string, body: any) => any) {
  const posts: Array<{ url: string; body: any }> = [];
  (globalThis as any).localStorage = { getItem: () => 't', setItem: () => {}, removeItem: () => {} };
  (globalThis as any).fetch = async (url: string, opts?: any) => {
    const path = String(url);
    if (opts?.method === 'POST') {
      const body = opts.body ? JSON.parse(opts.body) : {};
      posts.push({ url: path, body });
      const res = onPost?.(path, body);
      if (res?.fail) {
        return { ok: false, status: 422, json: async () => res.fail } as Response;
      }
      return { ok: true, json: async () => res ?? {} } as Response;
    }
    if (path.includes('/settings/telegram')) return { ok: true, json: async () => settings } as Response;
    return { ok: true, json: async () => ({}) } as Response;
  };
  return posts;
}

const configured = {
  configured: true, has_token: true, token_source: 'panel',
  chat_ids: '111, -100222', running: true, backup_delivery: false
};

describe('SystemHealthView Telegram card', () => {
  beforeEach(() => { toasts.length = 0; });
  afterEach(() => vi.restoreAllMocks());

  it('shows the configured chat ids and never a token', async () => {
    api(configured);
    render(SystemHealthView);
    const chats = (await screen.findByTestId('tg-chats')) as HTMLInputElement;
    await waitFor(() => expect(chats.value).toBe('111, -100222'));
    // The endpoint does not return the token, and the field must start empty:
    // an empty field means "keep what is stored".
    expect((screen.getByTestId('tg-token') as HTMLInputElement).value).toBe('');
  });

  it('omits the token when none was typed, so saving chat ids cannot wipe it', async () => {
    const posts = api(configured);
    render(SystemHealthView);
    const chats = (await screen.findByTestId('tg-chats')) as HTMLInputElement;
    await waitFor(() => expect(chats.value).toBe('111, -100222'));
    await fireEvent.input(chats, { target: { value: '111' } });
    await fireEvent.click(screen.getByTestId('tg-save'));
    await waitFor(() => expect(posts.length).toBeGreaterThan(0));
    expect(posts[0].body).not.toHaveProperty('token');
    expect(posts[0].body).toMatchObject({ chat_ids: '111', test: true });
  });

  it('sends the token when one is typed', async () => {
    const posts = api(configured);
    render(SystemHealthView);
    // Wait for the load to land first: loadTelegram clears the token field when
    // it resolves, so typing before that is silently discarded and the test
    // would fail for a reason unrelated to what it is checking.
    const chats = (await screen.findByTestId('tg-chats')) as HTMLInputElement;
    await waitFor(() => expect(chats.value).toBe('111, -100222'));
    await fireEvent.input(screen.getByTestId('tg-token'), { target: { value: 'new-token' } });
    await fireEvent.click(screen.getByTestId('tg-save'));
    await waitFor(() => expect(posts.length).toBeGreaterThan(0));
    expect(posts[0].body.token).toBe('new-token');
  });

  it('tests without saving', async () => {
    const posts = api(configured);
    render(SystemHealthView);
    await screen.findByTestId('tg-test');
    await fireEvent.click(screen.getByTestId('tg-test'));
    await waitFor(() => expect(posts.length).toBeGreaterThan(0));
    expect(posts[0].url).toContain('/settings/telegram/test');
    expect(posts[0].body.test).toBe(false);
  });

  // Telegram says "Unauthorized" when a token is wrong, which almost nobody
  // reads that way. The remediation is the part that helps.
  it('shows the remediation when Telegram refuses', async () => {
    api(configured, () => ({
      fail: {
        error: 'telegram: chat 111: Unauthorized',
        remediation: 'the bot token is wrong or has been revoked; create a new one with @BotFather'
      }
    }));
    render(SystemHealthView);
    await screen.findByTestId('tg-test');
    await fireEvent.click(screen.getByTestId('tg-test'));
    expect((await screen.findByTestId('tg-error')).textContent).toContain('Unauthorized');
    expect((await screen.findByTestId('tg-remedy')).textContent).toContain('BotFather');
  });

  it('reports whether the bot is actually running', async () => {
    api({ ...configured, running: false });
    render(SystemHealthView);
    expect((await screen.findByTestId('tg-status')).textContent).toContain('not running');
  });
});
