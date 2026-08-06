import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import OverviewView from './OverviewView.svelte';

describe('OverviewView Component', () => {
  let fetchCount = 0;
  beforeEach(() => {
    fetchCount = 0;
  });

  it('fetches and renders system health stats', async () => {
    (globalThis as any).fetch = async () => {
      fetchCount++;
      return {
        ok: true,
        json: async () => ({
          status: 'healthy',
          version: '1.0.0',
          nodes_online: 3,
          nodes_total: 3,
          uptime_seconds: 7200
        })
      } as Response;
    };

    render(OverviewView);

    const refreshBtn = await screen.findByText('Refresh');
    expect(refreshBtn).toBeTruthy();

    expect(await screen.findByText('healthy')).toBeTruthy();
    expect(screen.getByText('1.0.0')).toBeTruthy();
    expect(screen.getByText((content) => content.includes('3 / 3'))).toBeTruthy();
    expect(screen.getByText('2h 0m')).toBeTruthy();

    await fireEvent.click(refreshBtn);
    expect(fetchCount).toBeGreaterThanOrEqual(2);
  });
});
