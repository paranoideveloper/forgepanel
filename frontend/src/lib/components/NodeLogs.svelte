<script lang="ts">
  import { onDestroy } from 'svelte';
  import { tr } from '$lib/i18n';
  import { getAuthToken } from '$lib/api';

  let { nodeId, nodeName }: { nodeId: number; nodeName: string } = $props();

  let lines = $state<string[]>([]);
  // Named `conn`, not `state`: a local called `state` in a runes component
  // shadows the `$state` rune for the type checker, and every rune in the
  // file then reports "used before its declaration".
  let conn = $state<'connecting' | 'open' | 'closed'>('connecting');
  let ws: WebSocket | null = null;

  // The token goes in the QUERY, not a header.
  //
  // `new WebSocket()` takes a URL and nothing else — there is no way to set an
  // Authorization header on it — so a route mounted behind the panel's ordinary
  // header auth answers 401 for the only client that will ever call it, with a
  // perfectly correct handler behind it and every Go test passing. The server
  // accepts a query token on the handshake and only on the handshake; see
  // auth.bearer.
  function url(): string {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${location.host}/api/admin/nodes/${nodeId}/logs?access_token=${encodeURIComponent(getAuthToken())}`;
  }

  // The panel replays what it already holds before anything live, so a node that
  // failed ten minutes ago still explains itself when the panel is opened now.
  // Bounded here as well as on the server: a core that is looping would
  // otherwise grow this list for as long as the panel stays open.
  const MAX_LINES = 2000;

  function connect() {
    try {
      ws = new WebSocket(url());
    } catch {
      conn = 'closed';
      return;
    }
    ws.onopen = () => (conn = 'open');
    ws.onmessage = (ev) => {
      // Empty frames are the server's keepalive: a node that is behaving says
      // nothing for hours and an idle proxy would close a stream that is fine.
      if (typeof ev.data !== 'string' || ev.data === '') return;
      lines = [...lines, ev.data].slice(-MAX_LINES);
    };
    ws.onclose = () => (conn = 'closed');
    ws.onerror = () => (conn = 'closed');
  }
  connect();

  onDestroy(() => {
    // Closing the panel must close the socket. Leaving it open holds a
    // subscription on the server for every time an operator opened the panel
    // this session.
    ws?.close();
    ws = null;
  });
</script>

<div class="node-logs" data-testid="node-logs">
  <p class="muted">
    {#if conn === 'connecting'}{tr('nodes.logs_connecting')}
    {:else if conn === 'open'}{tr('nodes.logs_streaming', { p1: nodeName })}
    {:else}{tr('nodes.logs_disconnected')}{/if}
  </p>
  <pre data-testid="node-log-lines">{lines.join('\n')}</pre>
</div>

<style>
  .node-logs pre {
    max-height: 55vh;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-all;
    font-size: 0.8rem;
    line-height: 1.45;
    margin: 0;
  }
</style>
