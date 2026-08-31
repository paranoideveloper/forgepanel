import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import EnginesView from './EnginesView.svelte';

// The engines subsystem reported live core state and had no UI, so the question
// an operator asks when an inbound is not working — "is the core that serves it
// even running?" — could only be answered with curl.
const engines = [
  {
    engine: 'xray',
    state: 'running',
    pid: 51197,
    restarts: 1,
    responsive: true,
    recent_logs: ['Xray 26.3.27 started', 'accepted tcp:127.0.0.1:2055']
  },
  {
    engine: 'sing-box',
    state: 'running',
    pid: 51211,
    restarts: 0,
    responsive: true,
    recent_logs: []
  },
  {
    engine: 'kernel-wg',
    state: 'running',
    details: { interfaces: [{ interface: 'wg51831', up: true }], kernel: { tools_installed: true, module_loaded: true, kernel_ready: true } }
  },
  {
    engine: 'amneziawg',
    state: 'unavailable',
    last_error: 'awg/awg-quick tools not installed',
    details: { interfaces: [], kernel: { tools_installed: false, module_loaded: false, kernel_ready: false } }
  }
];

describe('EnginesView', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    (globalThis as any).fetch = async () => ({ ok: true, json: async () => engines }) as Response;
  });
  afterEach(() => vi.useRealTimers());

  it('names every core and the state it is actually in', async () => {
    render(EnginesView);
    for (const name of ['xray', 'sing-box', 'kernel-wg', 'amneziawg']) {
      expect(await screen.findByText(name)).toBeTruthy();
    }
    // Three running and one unavailable, so both states must be distinguishable.
    expect(screen.getAllByText('running').length).toBe(3);
    expect(screen.getByText('unavailable')).toBeTruthy();
  });

  it('shows the kernel interface a WireGuard inbound is actually served on', async () => {
    render(EnginesView);
    // Without this the operator cannot tell that choosing the kernel datapath
    // did anything at all.
    expect(await screen.findByText('wg51831')).toBeTruthy();
  });

  it('reports why an unavailable core is unavailable', async () => {
    render(EnginesView);
    // "unavailable" is a missing package, not a crash; the reason is what tells
    // the operator to install something rather than read a log.
    expect(await screen.findByText('awg/awg-quick tools not installed')).toBeTruthy();
  });

  it('keeps the recent log behind a toggle', async () => {
    render(EnginesView);
    const toggle = await screen.findByText('Show recent log');
    expect(screen.queryByText((t) => t.includes('Xray 26.3.27 started'))).toBeNull();
    await fireEvent.click(toggle);
    expect(screen.getByText((t) => t.includes('Xray 26.3.27 started'))).toBeTruthy();
  });

  it('offers only one log toggle: the core with no lines has nothing to show', async () => {
    render(EnginesView);
    await screen.findByText('xray');
    expect(screen.getAllByText('Show recent log').length).toBe(1);
  });
});
