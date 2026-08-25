import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import UsageView from './UsageView.svelte';
import TrafficChart from '$lib/components/TrafficChart.svelte';

const series = (n: number) =>
  Array.from({ length: n }, (_, i) => ({
    bucket: new Date(Date.UTC(2026, 7, 25, i)).toISOString(),
    bytes: (i + 1) * 1000
  }));

function mockApi(over: Record<string, unknown> = {}) {
  (globalThis as any).fetch = vi.fn(async (url: string) => {
    if (url.includes('/traffic/top')) {
      return { ok: true, json: async () => (over.top ?? { items: [{ key: '1', bytes: 9000 }, { key: '2', bytes: 500 }] }) } as any;
    }
    if (url.includes('/traffic/series')) {
      return { ok: true, json: async () => (over.series ?? { points: series(4) }) } as any;
    }
    if (url.includes('/admin/users')) {
      return { ok: true, json: async () => [{ id: 1, username: 'alice' }, { id: 2, username: 'bob' }] } as any;
    }
    return { ok: true, json: async () => ({}) } as any;
  });
}

describe('UsageView', () => {
  it('ranks top consumers and charts the heaviest by default', async () => {
    mockApi();
    render(UsageView);

    // Names, not ids: "alice" is what an operator is looking for.
    expect(await screen.findByText('alice')).toBeTruthy();
    expect(screen.getByText('bob')).toBeTruthy();
    // The heaviest consumer is selected without being asked for — it is the one
    // being looked for.
    expect((await screen.findAllByTestId('bar')).length).toBe(4);
  });

  it('charts a different consumer on request', async () => {
    let lastSeries = '';
    (globalThis as any).fetch = vi.fn(async (url: string) => {
      if (url.includes('/traffic/top')) {
        return { ok: true, json: async () => ({ items: [{ key: '1', bytes: 9000 }, { key: '2', bytes: 500 }] }) } as any;
      }
      if (url.includes('/traffic/series')) {
        lastSeries = url;
        return { ok: true, json: async () => ({ points: series(2) }) } as any;
      }
      if (url.includes('/admin/users')) {
        return { ok: true, json: async () => [{ id: 1, username: 'alice' }, { id: 2, username: 'bob' }] } as any;
      }
      return { ok: true, json: async () => ({}) } as any;
    });

    render(UsageView);
    const picks = await screen.findAllByTestId('pick');
    await fireEvent.click(picks[1]);
    expect(lastSeries).toContain('key=2');
  });

  it('switches resolution', async () => {
    let lastTop = '';
    (globalThis as any).fetch = vi.fn(async (url: string) => {
      if (url.includes('/traffic/top')) {
        lastTop = url;
        return { ok: true, json: async () => ({ items: [] }) } as any;
      }
      if (url.includes('/traffic/series')) return { ok: true, json: async () => ({ points: [] }) } as any;
      return { ok: true, json: async () => [] } as any;
    });
    render(UsageView);
    await screen.findByTestId('period-day');
    await fireEvent.click(screen.getByTestId('period-day'));
    expect(lastTop).toContain('period=day');
  });

  // A fresh install has no history, and saying so beats an empty table that
  // reads like a broken page.
  it('explains an empty history rather than showing a blank table', async () => {
    mockApi({ top: { items: [] }, series: { points: [] } });
    render(UsageView);
    expect((await screen.findByTestId('top-empty')).textContent).toContain('No usage recorded yet');
  });

  // Names are a nicety; failing to fetch them must not stop the charts.
  it('still charts when the user list cannot be fetched', async () => {
    (globalThis as any).fetch = vi.fn(async (url: string) => {
      if (url.includes('/admin/users')) return { ok: false, status: 403, json: async () => ({ error: 'nope' }) } as any;
      if (url.includes('/traffic/top')) return { ok: true, json: async () => ({ items: [{ key: '7', bytes: 10 }] }) } as any;
      return { ok: true, json: async () => ({ points: series(1) }) } as any;
    });
    render(UsageView);
    // Falls back to the raw key rather than hiding a real consumer.
    expect(await screen.findByText('7')).toBeTruthy();
  });
});

describe('TrafficChart', () => {
  it('draws one bar per bucket', () => {
    render(TrafficChart, { props: { points: series(6) } });
    expect(screen.getAllByTestId('bar').length).toBe(6);
  });

  it('shows the total, which is the number people actually want', () => {
    render(TrafficChart, { props: { points: [{ bucket: '2026-08-25T00:00:00Z', bytes: 1024 * 1024 }] } });
    expect(screen.getByTestId('chart-total').textContent).toMatch(/^1(\.0)? MB$/);
  });

  // An all-zero series must render a flat baseline, not divide by zero.
  it('survives an all-zero series', () => {
    render(TrafficChart, {
      props: { points: [{ bucket: '2026-08-25T00:00:00Z', bytes: 0 }, { bucket: '2026-08-25T01:00:00Z', bytes: 0 }] }
    });
    expect(screen.getAllByTestId('bar').length).toBe(2);
  });

  it('says so when there is nothing to plot', () => {
    render(TrafficChart, { props: { points: [] } });
    expect(screen.getByTestId('chart-empty')).toBeTruthy();
  });
});
