import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import NodeLogs from './NodeLogs.svelte';
import { setAuthToken } from '$lib/api';

// The failure this file exists for cannot be seen from Go.
//
// The panel's admin API authenticates from the Authorization header. A browser's
// `new WebSocket()` takes a URL and nothing else — there is no way to set a
// header on it — so the log route can be mounted correctly, behind a correct
// handler, with every Go test passing, and still answer 401 for the only client
// that will ever call it. Nothing server-side can notice; this can.

class FakeSocket {
  static last: FakeSocket | null = null;
  url: string;
  closed = false;
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(url: string) {
    this.url = url;
    FakeSocket.last = this;
  }
  close() {
    this.closed = true;
  }
}

describe('NodeLogs', () => {
  beforeEach(() => {
    FakeSocket.last = null;
    setAuthToken('tok-abc');
    (globalThis as any).WebSocket = FakeSocket;
  });
  afterEach(() => {
    setAuthToken('');
  });

  it('carries the session token in the URL, because a WebSocket cannot send a header', () => {
    render(NodeLogs, { props: { nodeId: 7, nodeName: 'fra1' } });

    const url = FakeSocket.last!.url;
    expect(url).toContain('/api/admin/nodes/7/logs');
    expect(url).toContain('access_token=tok-abc');
  });

  it('renders the lines the node reported', async () => {
    render(NodeLogs, { props: { nodeId: 7, nodeName: 'fra1' } });
    const ws = FakeSocket.last!;
    ws.onopen!();
    ws.onmessage!({ data: 'xray: failed to start inbound in-443' });
    ws.onmessage!({ data: 'xray: address already in use' });

    await waitFor(() => {
      expect(screen.getByTestId('node-log-lines').textContent).toContain('address already in use');
    });
  });

  it('ignores the keepalive frames', async () => {
    render(NodeLogs, { props: { nodeId: 7, nodeName: 'fra1' } });
    const ws = FakeSocket.last!;
    ws.onopen!();
    // A node that is behaving says nothing for hours, so the server sends empty
    // frames to stop an idle proxy closing a stream that is working. Rendering
    // them would fill the panel with blank lines.
    ws.onmessage!({ data: '' });
    ws.onmessage!({ data: 'core: up' });

    await waitFor(() => {
      expect(screen.getByTestId('node-log-lines').textContent).toBe('core: up');
    });
  });

  it('closes the socket when the panel is closed', () => {
    const { unmount } = render(NodeLogs, { props: { nodeId: 7, nodeName: 'fra1' } });
    const ws = FakeSocket.last!;
    unmount();
    // Otherwise every time the operator opens the panel leaves a subscription
    // behind on the server for the life of the session.
    expect(ws.closed).toBe(true);
  });

  it('says so when the stream closes, rather than showing a frozen box', async () => {
    render(NodeLogs, { props: { nodeId: 7, nodeName: 'fra1' } });
    FakeSocket.last!.onclose!();
    await waitFor(() => {
      expect(screen.getByText(/log stream closed/)).toBeTruthy();
    });
  });
});
