import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import NodesView from './NodesView.svelte';

describe('NodesView Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.stubGlobal('confirm', () => true);
    vi.stubGlobal('navigator', {
      clipboard: {
        writeText: vi.fn().mockResolvedValue(undefined)
      }
    });
  });

  it('loads node list (online and offline nodes) and registers node', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string, opts?: any) => {
      if (opts?.method === 'POST') {
        return Promise.resolve({ ok: true, json: async () => ({ id: 1, name: 'EU-Node' }) });
      }
      return Promise.resolve({
        ok: true,
        json: async () => [
          { id: 1, name: 'EU-Node', address: '1.2.3.4', cpu: 10, mem_mb: 512, healthy: true },
          { id: 2, name: 'Stale-Node', address: '2.2.2.2', cpu: 0, mem_mb: 0, healthy: false }
        ]
      });
    }));

    render(NodesView);

    expect(await screen.findByText('EU-Node')).toBeTruthy();
    expect(screen.getByText('Stale-Node')).toBeTruthy();
    expect(screen.getByText('Stale')).toBeTruthy();

    const nameInput = screen.getByPlaceholderText('Node Name (e.g. EU-West-1)');
    const addrInput = screen.getByPlaceholderText('Public IP or Domain');

    await fireEvent.input(nameInput, { target: { value: 'US-Node' } });
    await fireEvent.input(addrInput, { target: { value: '5.6.7.8' } });

    const registerBtn = screen.getByText('Register Node');
    await fireEvent.click(registerBtn);

    expect(fetch).toHaveBeenCalledWith('/api/admin/nodes', expect.objectContaining({ method: 'POST' }));
  });

  it('validates node registration inputs', async () => {
    render(NodesView);
    const registerBtn = screen.getByText('Register Node');
    await fireEvent.click(registerBtn);
    expect(await screen.findByText('Both Name and Address are required')).toBeTruthy();
  });

  it('deletes a node and opens install script modal', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string, opts?: any) => {
      if (opts?.method === 'DELETE') {
        return Promise.resolve({ ok: true, json: async () => ({ deleted: 1 }) });
      }
      return Promise.resolve({
        ok: true,
        json: async () => [
          { id: 1, name: 'EU-Node', address: '1.2.3.4', healthy: true }
        ]
      });
    }));

    render(NodesView);

    const deleteBtn = await screen.findByText('Remove');
    await fireEvent.click(deleteBtn);
    expect(fetch).toHaveBeenCalledWith('/api/admin/nodes/1', expect.objectContaining({ method: 'DELETE' }));

    const scriptBtn = screen.getByText('Install Agent Script');
    await fireEvent.click(scriptBtn);

    expect(screen.getByText('Deploy Node Agent (forgenode)')).toBeTruthy();

    const copyBtn = screen.getByText('Copy Command');
    await fireEvent.click(copyBtn);
    expect(navigator.clipboard.writeText).toHaveBeenCalled();
  });

  it('handles confirmation cancel and clipboard error in script copy', async () => {
    vi.stubGlobal('confirm', () => false);
    vi.stubGlobal('navigator', {
      clipboard: {
        writeText: vi.fn().mockRejectedValue(new Error('Copy error'))
      }
    });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [{ id: 1, name: 'EU-Node', address: '1.2.3.4', healthy: true }]
    }));

    render(NodesView);

    const deleteBtn = await screen.findByText('Remove');
    await fireEvent.click(deleteBtn);
    expect(fetch).not.toHaveBeenCalledWith('/api/admin/nodes/1', expect.objectContaining({ method: 'DELETE' }));

    const scriptBtn = screen.getByText('Install Agent Script');
    await fireEvent.click(scriptBtn);

    const copyBtn = screen.getByText('Copy Command');
    await fireEvent.click(copyBtn);
  });

  it('handles error responses in loadNodes and registerNode', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Node API failure')));

    render(NodesView);

    const nameInput = screen.getByPlaceholderText('Node Name (e.g. EU-West-1)');
    const addrInput = screen.getByPlaceholderText('Public IP or Domain');

    await fireEvent.input(nameInput, { target: { value: 'ErrNode' } });
    await fireEvent.input(addrInput, { target: { value: '9.9.9.9' } });

    const registerBtn = screen.getByText('Register Node');
    await fireEvent.click(registerBtn);

    expect(await screen.findByText('Node API failure')).toBeTruthy();
  });
});
