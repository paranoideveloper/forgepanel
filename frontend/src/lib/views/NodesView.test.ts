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
    let postCalled = false;
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'POST') {
        postCalled = true;
        return { ok: true, json: async () => ({ id: 1, name: 'EU-Node' }) } as Response;
      }
      return {
        ok: true,
        json: async () => [
          { id: 1, name: 'EU-Node', address: '1.2.3.4', cpu: 10, mem_mb: 512, healthy: true },
          { id: 2, name: 'Stale-Node', address: '2.2.2.2', cpu: 0, mem_mb: 0, healthy: false }
        ]
      } as Response;
    };

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

    expect(postCalled).toBe(true);
  });

  it('validates node registration inputs', async () => {
    render(NodesView);
    const registerBtn = screen.getByText('Register Node');
    await fireEvent.click(registerBtn);
    expect(await screen.findByText('Both Name and Address are required')).toBeTruthy();
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

    const scriptBtn = screen.getByText('Install Agent Script');
    await fireEvent.click(scriptBtn);

    expect(screen.getByText('Deploy Node Agent (forgenode)')).toBeTruthy();

    const copyBtn = screen.getByText('Copy Command');
    await fireEvent.click(copyBtn);
    expect(copyCalled).toBe(true);
  });

  it('handles confirmation cancel and clipboard error in script copy', async () => {
    let deleteCalled = false;
    (globalThis as any).confirm = () => false;
    (globalThis as any).navigator = {
      clipboard: {
        writeText: async () => { throw new Error('Copy error'); }
      }
    };
    (globalThis as any).fetch = async (url: string, opts?: any) => {
      if (opts?.method === 'DELETE') deleteCalled = true;
      return {
        ok: true,
        json: async () => [{ id: 1, name: 'EU-Node', address: '1.2.3.4', healthy: true }]
      } as Response;
    };

    render(NodesView);

    const deleteBtn = await screen.findByText('Remove');
    await fireEvent.click(deleteBtn);
    expect(deleteCalled).toBe(false);

    const scriptBtn = screen.getByText('Install Agent Script');
    await fireEvent.click(scriptBtn);

    const copyBtn = screen.getByText('Copy Command');
    await fireEvent.click(copyBtn);
  });

  it('handles error responses in loadNodes and registerNode', async () => {
    (globalThis as any).fetch = async () => { throw new Error('Node API failure'); };

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
