import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import NodesView from './NodesView.svelte';

describe('NodesView Component', () => {
  beforeEach(() => {
    (globalThis as any).confirm = () => true;
    (globalThis as any).navigator = {
      clipboard: {
        writeText: async () => {}
      }
    };
  });

  it('loads node list (online and offline nodes) and registers node', async () => {
    // The view used to POST /admin/nodes, which the server does not register —
    // every registration 404'd. Assert the REAL route, not merely that some POST
    // happened, which is what let the 404 go unnoticed.
    let postedTo = '';
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'POST') {
        postedTo = url;
        return {
          ok: true,
          json: async () => ({ id: 1, name: 'US-Node', enroll_command: 'curl -fsSL https://p/node-install.sh | PANEL=https://p TOKEN=realtoken bash' })
        } as Response;
      }
      return {
        ok: true,
        json: async () => [
          // `status` is derived server-side on every read and is what the badge
          // renders. It has to come from there: three of its four states —
          // disabled, a node-reported core failure, and an install in progress —
          // are invisible to anything working from last_seen alone.
          {
            id: 1, name: 'EU-Node', address: '1.2.3.4', cpu: 10, mem_mb: 512, healthy: true,
            status: 'connected', last_seen: new Date(Date.now() - 20_000).toISOString()
          },
          {
            id: 2, name: 'Stale-Node', address: '2.2.2.2', cpu: 0, mem_mb: 0, healthy: false,
            status: 'error', status_message: 'no heartbeat for 2h0m0s'
          }
        ]
      } as Response;
    };

    render(NodesView);

    expect(await screen.findByText('EU-Node')).toBeTruthy();
    expect(screen.getByText('Stale-Node')).toBeTruthy();
    expect(screen.getByTestId('node-status-1').textContent?.trim()).toBe('Connected');
    expect(screen.getByTestId('node-status-2').textContent?.trim()).toBe('Error');
    // An error badge with no reason sends the operator to the server to find one.
    expect(screen.getByTestId('node-status-msg-2').textContent).toContain('no heartbeat');

    const nameInput = screen.getByPlaceholderText('Node Name (e.g. EU-West-1)');
    const addrInput = screen.getByPlaceholderText('Public IP or Domain (optional)');

    await fireEvent.input(nameInput, { target: { value: 'US-Node' } });
    await fireEvent.input(addrInput, { target: { value: '5.6.7.8' } });

    const registerBtn = screen.getByText('Register Node');
    await fireEvent.click(registerBtn);

    expect(postedTo).toContain('/admin/nodes/enroll');
  });

  // The address is optional on the server: a node behind NAT or on a dynamic IP
  // reports its own when it registers. Demanding one here blocked exactly the
  // nodes that most need enrolling.
  it('requires only a name, since the server treats the address as optional', async () => {
    let postedBody: any = null;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'POST') {
        postedBody = JSON.parse(opts.body);
        return { ok: true, json: async () => ({ name: 'NAT-Node', enroll_command: 'cmd' }) } as Response;
      }
      return { ok: true, json: async () => [] } as Response;
    };
    render(NodesView);

    // No name at all: refuse, and say what is missing.
    await fireEvent.click(screen.getByText('Register Node'));
    expect(await screen.findByText('A node name is required')).toBeTruthy();
    expect(postedBody).toBeNull();

    // Name only: accepted.
    await fireEvent.input(screen.getByPlaceholderText('Node Name (e.g. EU-West-1)'), {
      target: { value: 'NAT-Node' }
    });
    await fireEvent.click(screen.getByText('Register Node'));
    expect(postedBody?.name).toBe('NAT-Node');
  });

  // The enroll token is minted once and never returned again. The modal used to
  // show a command containing the literal string YOUR_ENROLL_TOKEN, which looks
  // copy-pasteable and cannot work.
  it('shows the real enrollment command returned by the server', async () => {
    const real = 'curl -fsSL https://panel/node-install.sh | PANEL=https://panel TOKEN=abc123 PANEL_FINGERPRINT=ff bash';
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'POST') {
        return {
          ok: true,
          json: async () => ({ name: 'EU-1', enroll_command: real, panel_fingerprint: 'ff' })
        } as Response;
      }
      return { ok: true, json: async () => [] } as Response;
    };
    render(NodesView);

    await fireEvent.input(screen.getByPlaceholderText('Node Name (e.g. EU-West-1)'), {
      target: { value: 'EU-1' }
    });
    await fireEvent.click(screen.getByText('Register Node'));

    const cmd = await screen.findByTestId('enroll-command');
    expect(cmd.textContent).toBe(real);
    expect(cmd.textContent).not.toContain('YOUR_ENROLL_TOKEN');
    // The operator must be told the token cannot be shown again.
    expect(screen.getByText(/appears once/)).toBeTruthy();
  });

  it('deletes a node and opens install script modal', async () => {
    let deleteCalled = false;
    let copyCalled = false;
    (globalThis as any).navigator.clipboard.writeText = async () => { copyCalled = true; };
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'DELETE') {
        deleteCalled = true;
        return { ok: true, json: async () => ({ deleted: 1 }) } as Response;
      }
      return {
        ok: true,
        json: async () => [
          { id: 1, name: 'EU-Node', address: '1.2.3.4', healthy: true }
        ]
      } as Response;
    };

    render(NodesView);

    const deleteBtn = await screen.findByText('Remove');
    await fireEvent.click(deleteBtn);
    expect(deleteCalled).toBe(true);

    // The enroll token is minted per node when it is registered, and cannot be
    // reissued, so there is no generic command to hand out. The button opens the
    // modal and says so rather than showing a placeholder that cannot work.
    const scriptBtn = screen.getByText('Install Agent Script');
    await fireEvent.click(scriptBtn);

    expect(screen.getByText('Deploy Node Agent (forgenode)')).toBeTruthy();
    expect(screen.getByText(/Register a node above/)).toBeTruthy();
    expect(screen.queryByText('Copy Command')).toBeNull();
    expect(copyCalled).toBe(false);
  });

  it('handles confirmation cancel and clipboard error in script copy', async () => {
    let copyAttempted = false;
    (globalThis as any).confirm = () => false;
    (globalThis as any).navigator.clipboard.writeText = async () => {
      copyAttempted = true;
      throw new Error('denied');
    };
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'DELETE') {
        throw new Error('delete should not be reached when the operator cancels');
      }
      if (opts?.method === 'POST') {
        return { ok: true, json: async () => ({ name: 'N', enroll_command: 'the-real-command' }) } as Response;
      }
      return {
        ok: true,
        json: async () => [{ id: 1, name: 'EU-Node', address: '1.2.3.4', healthy: true }]
      } as Response;
    };

    render(NodesView);

    // Cancelling the confirm must not delete.
    await fireEvent.click(await screen.findByText('Remove'));

    // A copy failure must be surfaced, not swallowed. Reach the copy button the
    // way an operator does: by registering a node.
    await fireEvent.input(screen.getByPlaceholderText('Node Name (e.g. EU-West-1)'), {
      target: { value: 'N' }
    });
    await fireEvent.click(screen.getByText('Register Node'));
    await fireEvent.click(await screen.findByText('Copy Command'));
    expect(copyAttempted).toBe(true);
  });

  it('handles error responses in loadNodes and registerNode', async () => {
    (globalThis as any).fetch = async () => { throw new Error('Node API failure'); };

    render(NodesView);

    const nameInput = screen.getByPlaceholderText('Node Name (e.g. EU-West-1)');
    const addrInput = screen.getByPlaceholderText('Public IP or Domain (optional)');

    await fireEvent.input(nameInput, { target: { value: 'ErrNode' } });
    await fireEvent.input(addrInput, { target: { value: '9.9.9.9' } });

    const registerBtn = screen.getByText('Register Node');
    await fireEvent.click(registerBtn);

    expect(await screen.findByText('Node API failure')).toBeTruthy();
  });

  // The heartbeat carries disk, connection count, core uptime, last-seen,
  // enrolled and config_dirty. None of them appeared anywhere in the table, so
  // the two conditions that actually take a node down — a full disk and a
  // crash-looping core — were invisible while the node still showed "Online".
  it('shows disk, connections, core uptime and last-seen', async () => {
    (globalThis as any).fetch = async () =>
      ({
        ok: true,
        json: async () => [
          {
            id: 1, name: 'EU-Node', address: '1.2.3.4', healthy: true, enrolled: true,
            cpu: 12, mem_mb: 900, disk_used_mb: 4096, disk_total_mb: 20480,
            tcp_conns: 37, core_uptime_sec: 7200, core_version: '26.2.6',
            last_seen: new Date(Date.now() - 30_000).toISOString()
          }
        ]
      }) as Response;

    render(NodesView);

    expect(await screen.findByText('EU-Node')).toBeTruthy();
    expect(screen.getByText('4.0 / 20.0 GB')).toBeTruthy();
    expect(screen.getByText('37')).toBeTruthy();
    expect(screen.getByText('2h')).toBeTruthy();
    expect(screen.getByText(/30s ago/)).toBeTruthy();
  });

  // A node that is connected but whose core never stays up is the case a status
  // badge alone cannot express.
  it('reports a core that is not running as down, even while the node is online', async () => {
    (globalThis as any).fetch = async () =>
      ({
        ok: true,
        json: async () => [
          {
            id: 1, name: 'Flapping', address: '1.2.3.4', healthy: true, enrolled: true,
            cpu: 5, mem_mb: 100, core_uptime_sec: 0, tcp_conns: 0,
            disk_used_mb: 19000, disk_total_mb: 20480,
            last_seen: new Date().toISOString()
          }
        ]
      }) as Response;

    render(NodesView);

    expect(await screen.findByText('Flapping')).toBeTruthy();
    expect(screen.getByText('down')).toBeTruthy();
    // 92% full: the operator has to be told before writes start failing.
    expect(screen.getByTitle(/will stop writing configs/)).toBeTruthy();
  });

  // A node registered but never checked in looks identical to a working one
  // without this.
  it('marks a registered node whose agent has never checked in', async () => {
    (globalThis as any).fetch = async () =>
      ({
        ok: true,
        json: async () => [
          { id: 1, name: 'Pending', address: '', healthy: false, enrolled: false, cpu: 0, mem_mb: 0 }
        ]
      }) as Response;

    render(NodesView);
    expect(await screen.findByText('Not enrolled')).toBeTruthy();
    expect(screen.getByText('never')).toBeTruthy();
  });

  // The badge used to read the `healthy` field straight off the payload, and
  // that field is only ever written true on the server — nothing anywhere sets
  // it false. So a node that stopped reporting an hour ago rendered "Online"
  // beside a last-seen cell reading "1h ago", and the badge was decorative.
  it('shows the state the server derived, not the healthy flag the payload claims', async () => {
    (globalThis as any).fetch = async () =>
      ({
        ok: true,
        json: async () => [
          {
            id: 7, name: 'Zombie', address: '1.2.3.4', healthy: true, enrolled: true,
            cpu: 0, mem_mb: 0, status: 'error', status_message: 'no heartbeat for 1h0m0s',
            last_seen: new Date(Date.now() - 60 * 60 * 1000).toISOString()
          }
        ]
      }) as Response;

    render(NodesView);

    expect(await screen.findByText('Zombie')).toBeTruthy();
    // Assert the badge itself, not merely that the word appears somewhere: the
    // table has a Status column header and other badges in the same cell.
    expect(screen.getByTestId('node-status-7').textContent?.trim()).toBe('Error');
    expect(screen.getByText('1h ago')).toBeTruthy();
  });

  // Four states, because before this a node mid-install, a node that had died,
  // a node whose core refuses every config and a node the operator switched off
  // all rendered the same badge — so the page reported four emergencies where
  // there was at most one.
  it('tells an install in progress apart from a dead node and one switched off', async () => {
    (globalThis as any).fetch = async () =>
      ({
        ok: true,
        json: async () => [
          { id: 1, name: 'Installing', address: '', healthy: false, enrolled: true, status: 'connecting' },
          { id: 2, name: 'Dead', address: '', healthy: false, enrolled: true, status: 'error' },
          { id: 3, name: 'Off', address: '', healthy: false, enrolled: true, status: 'disabled', disabled: true }
        ]
      }) as Response;

    render(NodesView);

    expect(await screen.findByText('Installing')).toBeTruthy();
    expect(screen.getByTestId('node-status-1').textContent?.trim()).toBe('Connecting');
    expect(screen.getByTestId('node-status-2').textContent?.trim()).toBe('Error');
    expect(screen.getByTestId('node-status-3').textContent?.trim()).toBe('Disabled');
    // Deliberately off must not wear the colour of a fault, or the operator
    // learns to ignore the colour.
    expect(screen.getByTestId('node-status-3').className).not.toContain('badge-err');
  });

  // The button has to reach the route that actually refuses the node's
  // heartbeat. A Disable control that only repaints the badge is worse than none:
  // it tells the operator a machine is off while it keeps serving traffic.
  it('disables a node through the PATCH route that gates its heartbeat', async () => {
    let patched: { url: string; body: any } | null = null;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'PATCH') {
        patched = { url, body: JSON.parse(opts.body) };
        return { ok: true, json: async () => ({ id: 1, disabled: true }) } as Response;
      }
      return {
        ok: true,
        json: async () => [
          { id: 1, name: 'EU-Node', address: '1.2.3.4', healthy: true, enrolled: true, status: 'connected' }
        ]
      } as Response;
    };

    render(NodesView);
    await fireEvent.click(await screen.findByText('Disable'));

    expect(patched).not.toBeNull();
    expect(patched!.url).toContain('/admin/nodes/1');
    expect(patched!.body).toEqual({ disabled: true });
  });

  // And back again, or the only way to re-enable a node is the database.
  it('offers Enable for a node that is already disabled', async () => {
    let patchedBody: any = null;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'PATCH') {
        patchedBody = JSON.parse(opts.body);
        return { ok: true, json: async () => ({ id: 1, disabled: false }) } as Response;
      }
      return {
        ok: true,
        json: async () => [
          { id: 1, name: 'Off', address: '1.2.3.4', healthy: false, enrolled: true, status: 'disabled', disabled: true }
        ]
      } as Response;
    };

    render(NodesView);
    await fireEvent.click(await screen.findByText('Enable'));

    expect(patchedBody).toEqual({ disabled: false });
  });
});
