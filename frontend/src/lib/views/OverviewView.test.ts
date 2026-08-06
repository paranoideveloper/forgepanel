import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import OverviewView from './OverviewView.svelte';

describe('OverviewView Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('fetches and renders system health stats', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        status: 'healthy',
        version: '1.0.0',
        nodes_online: 3,
        nodes_total: 3,
        uptime_seconds: 7200
      })
    }));

    render(OverviewView);

    const refreshBtn = await screen.findByText('Refresh');
    expect(refreshBtn).toBeTruthy();

    expect(await screen.findByText('healthy')).toBeTruthy();
    expect(screen.getByText('1.0.0')).toBeTruthy();
    expect(screen.getByText('3 / 3 Online')).toBeTruthy();
    expect(screen.getByText('2h 0m')).toBeTruthy();

    await fireEvent.click(refreshBtn);
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
