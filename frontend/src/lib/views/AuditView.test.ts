import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import AuditView from './AuditView.svelte';

// The panel wrote audit rows and nothing ever read them. The one consumer that
// looked like a reader fetched /admin/stats (which returns counts) typed as
// AuditLog[], so it iterated nothing.

const entry = (over: Partial<Record<string, unknown>> = {}) => ({
  id: 1,
  created_at: '2026-08-25T10:00:00Z',
  admin_id: 1,
  actor: 'owner',
  ip: '10.0.0.5',
  action: 'admin.create',
  target: 'reseller1 as reseller',
  diff: '',
  ...over
});

describe('AuditView', () => {
  it('renders entries with actor, IP and action', async () => {
    (globalThis as any).fetch = async (url: string) => {
      if (url.includes('/audit/actions')) {
        return { ok: true, json: async () => ({ actions: ['admin.create', 'login'] }) } as Response;
      }
      return {
        ok: true,
        json: async () => ({ items: [entry()], total: 1, limit: 50, offset: 0 })
      } as Response;
    };

    render(AuditView);

    expect(await screen.findByText('owner')).toBeTruthy();
    expect(screen.getByText('10.0.0.5')).toBeTruthy();
    // The target is unique to the row; the action also appears as a filter
    // <option>, so matching it alone would not prove the row rendered.
    expect(screen.getByText('reseller1 as reseller')).toBeTruthy();
    expect(screen.getAllByText('admin.create').length).toBeGreaterThanOrEqual(2);
  });

  // A page without a total says nothing about whether it is the whole story.
  it('reports the total, not just the page', async () => {
    (globalThis as any).fetch = async (url: string) => {
      if (url.includes('/audit/actions')) return { ok: true, json: async () => ({ actions: [] }) } as Response;
      return {
        ok: true,
        json: async () => ({ items: [entry()], total: 137, limit: 50, offset: 0 })
      } as Response;
    };
    render(AuditView);
    const pager = await screen.findByTestId('pager');
    expect(pager.textContent).toContain('137');
    expect(pager.textContent).toContain('Page 1 of 3');
  });

  it('sends the filters it was given', async () => {
    let asked = '';
    (globalThis as any).fetch = async (url: string) => {
      if (url.includes('/audit/actions')) {
        return { ok: true, json: async () => ({ actions: ['login'] }) } as Response;
      }
      asked = url;
      return { ok: true, json: async () => ({ items: [], total: 0, limit: 50, offset: 0 }) } as Response;
    };

    render(AuditView);
    await screen.findByTestId('filter-actor');
    await fireEvent.input(screen.getByTestId('filter-actor'), { target: { value: 'alice' } });
    await fireEvent.click(screen.getByText('Apply'));

    expect(asked).toContain('actor=alice');
  });

  // "Nothing recorded yet" and "no match" are different facts, and telling an
  // operator the wrong one sends them looking in the wrong place.
  it('distinguishes an empty trail from an empty filter result', async () => {
    (globalThis as any).fetch = async (url: string) => {
      if (url.includes('/audit/actions')) return { ok: true, json: async () => ({ actions: [] }) } as Response;
      return { ok: true, json: async () => ({ items: [], total: 0, limit: 50, offset: 0 }) } as Response;
    };
    render(AuditView);
    expect((await screen.findByTestId('empty')).textContent).toContain('Nothing recorded yet');

    await fireEvent.input(screen.getByTestId('filter-actor'), { target: { value: 'nobody' } });
    await fireEvent.click(screen.getByText('Apply'));
    expect((await screen.findByTestId('empty')).textContent).toContain('No entries match');
  });

  it('disables paging at the ends', async () => {
    (globalThis as any).fetch = async (url: string) => {
      if (url.includes('/audit/actions')) return { ok: true, json: async () => ({ actions: [] }) } as Response;
      return {
        ok: true,
        json: async () => ({ items: [entry()], total: 1, limit: 50, offset: 0 })
      } as Response;
    };
    render(AuditView);
    const prev = (await screen.findByText('Previous')) as HTMLButtonElement;
    const next = screen.getByText('Next') as HTMLButtonElement;
    expect(prev.disabled).toBe(true);
    expect(next.disabled).toBe(true);
  });

  // AuditLog.Diff was stored and served and never written, so entries said that
  // someone changed something and nothing about what. Now it is populated, the
  // view has to surface it — collapsed, because a diff is detail for the one
  // entry being investigated.
  it('shows what changed on demand', async () => {
    (globalThis as any).fetch = async (url: string) => {
      if (url.includes('/audit/actions')) return { ok: true, json: async () => ({ actions: [] }) } as Response;
      return {
        ok: true,
        json: async () => ({
          items: [entry({ diff: 'port: 443 → 8443; security.reality.private_key: changed' })],
          total: 1, limit: 50, offset: 0
        })
      } as Response;
    };

    render(AuditView);
    // Collapsed by default.
    await screen.findByTestId('toggle-diff');
    expect(screen.queryByTestId('diff')).toBeNull();

    await fireEvent.click(screen.getByTestId('toggle-diff'));
    const diff = await screen.findByTestId('diff');
    expect(diff.textContent).toContain('port: 443 → 8443');
    // The credential is named, never valued.
    expect(diff.textContent).toContain('private_key: changed');
  });

  it('offers no diff control for an entry that has none', async () => {
    (globalThis as any).fetch = async (url: string) => {
      if (url.includes('/audit/actions')) return { ok: true, json: async () => ({ actions: [] }) } as Response;
      return {
        ok: true,
        json: async () => ({ items: [entry({ diff: '' })], total: 1, limit: 50, offset: 0 })
      } as Response;
    };
    render(AuditView);
    await screen.findByText('owner');
    expect(screen.queryByTestId('toggle-diff')).toBeNull();
  });
});
